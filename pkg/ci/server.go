package ci

import (
	"fmt"
	"net/http"

	"github.com/golang/glog"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	ghub "golang.org/x/oauth2/github"
)

func startCIServer() error {
	addr := fmt.Sprintf("%s:%d", viper.GetString("ip"), viper.GetInt("port"))
	selfURL := viper.GetString("github-endpoint")
	webhookSecret := viper.GetString("webhook-secret")
	githubID := viper.GetString("github-client-id")
	githubSecret := viper.GetString("github-secret")

	conf := &oauth2.Config{
		ClientID:     githubID,
		ClientSecret: githubSecret,
		Scopes: []string{
			"repo",
		},
		Endpoint:    ghub.Endpoint,
		RedirectURL: selfURL,
	}

	s := &http.Server{
		Addr: addr,
		Handler: &ciHandler{
			config:        conf,
			selfURL:       selfURL,
			webhookSecret: []byte(webhookSecret),
		},
		ReadTimeout:    10 * time.Second,
		WriteTimeout:   10 * time.Second,
		MaxHeaderBytes: 1 << 20,
	}
	return s.ListenAndServe()
}

type ciHandler struct {
	config        *oauth2.Config
	token         *oauth2.Token
	selfURL       string
	webhookSecret []byte
}

func (c *ciHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/login" {
		if c.token != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		url := c.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/logs/") {
		vals := strings.Split(r.URL.Path, "/")
		sha := vals[len(vals)-1]
		logs, err := ioutil.ReadFile(filepath.Join("tmp", fmt.Sprintf("%s.log", sha)))
		if err != nil {
			log.Printf("error reading log file: %v", err)
			w.WriteHeader(http.StatusNotFound)
			w.Write([]byte(err.Error()))
			return
		}
		w.WriteHeader(http.StatusOK)
		w.Write(logs)
		return
	}

	if r.URL.Path == "/webhook" {
		payload, err := github.ValidatePayload(r, c.webhookSecret)
		if err != nil {
			log.Printf("error validating payload:%s %v", payload, err)
		}
		event, err := github.ParseWebHook(github.WebHookType(r), payload)
		if err != nil {
			log.Printf("error parsing webhook %v", err)
			return
		}

		if github.WebHookType(r) == "push" {
			go c.processPush(*(event.(*github.PushEvent)).After)
			return
		}
		if github.WebHookType(r) == "pull_request" {
			go c.processPullRequest(event.(*github.PullRequestEvent))
			return
		}
		log.Printf("unknown webhook type %s", github.WebHookType(r))
	}
	c.exchangeToken(w, r)
}

func (c *ciHandler) processPullRequest(pullRequestEvent *github.PullRequestEvent) {
	var tmpPort uint32
	if *(pullRequestEvent.Action) != "opened" && *(pullRequestEvent.Action) != "synchronize" {
		log.Printf("ignoring pull_request event: %s", *pullRequestEvent.Action)
		return
	}
	pr := pullRequestEvent.GetPullRequest()
	head := pr.GetHead()
	sha := *(head.SHA)
	repoName := *head.Repo.FullName
	branchRef := plumbing.NewBranchReferenceName(*head.Ref)

	if _, err := os.Stat(filepath.Join("tmp", sha)); !os.IsNotExist(err) {
		log.Printf("commit already processed")
		return
	}

	if err := c.updateStatus("minio", "minio", sha, github.String("pending")); err != nil {
		log.Printf("error updating status for minio/minio:%s %v", sha, err)
		return
	}
	doneStatus := "error"
	defer c.updateStatus("minio", "minio", sha, &doneStatus)

	f, err := os.OpenFile(filepath.Join("tmp", fmt.Sprintf("%s.log", sha)), os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		log.Printf("error opening log file: %v", err)
		return
	}
	defer f.Close()
	log := log.New(f, "", 0)

	portLock.Lock()
	tmpPort = *port
	newPort := atomic.AddUint32(port, 2)
	if newPort >= 65000 {
		newPort = 36000
	}
	port = &newPort
	portLock.Unlock()

	backendPort := tmpPort
	gatewayPort := tmpPort + 1

	oauthClient := c.config.Client(oauth2.NoContext, c.token)
	client := github.NewClient(oauthClient)
	repoVals := strings.Split(repoName, "/")
	repoOwner := repoVals[0]
	repoNameString := repoVals[1]
	repo, _, err := client.Repositories.Get(context.Background(), repoOwner, repoNameString)
	if err != nil {
		log.Printf("error getting repository: %v", err)
		return
	}
	defer os.RemoveAll(filepath.Join("tmp", sha))
	cloneURL := repo.GetCloneURL()

	localRepo, err := git.PlainClone(filepath.Join("tmp", sha, "minio", "minio"), false, &git.CloneOptions{
		URL:           cloneURL,
		Progress:      f,
		ReferenceName: branchRef,
	})
	if err != nil {
		log.Printf("error getting localRepo: %v", err)
		return
	}
	workTree, err := localRepo.Worktree()
	if err != nil {
		log.Printf("error getting worktree: %v", err)
		return
	}
	hash := plumbing.NewHash(sha)
	err = workTree.Checkout(&git.CheckoutOptions{
		Hash: hash,
	})
	if err != nil {
		log.Printf("error checking out rev: %s", sha)
		return
	}

	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("error getting current working directory: %v", err)
		return
	}
	cmd := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"run",
			"-v",
			fmt.Sprintf("%s:/go/src/github.com/minio/minio", filepath.Join(cwd, "tmp", sha, "minio", "minio")),
			"golang:1.10",
			"go",
			"build",
			"-o",
			"/go/src/github.com/minio/minio/minio",
			"github.com/minio/minio",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
	}
	err = cmd.Run()
	if err != nil {
		log.Printf("error building minio/minio %s: %v", sha, err)
		return
	}

	env := os.Environ()
	env = append(env, "MINIO_ACCESS_KEY=minio")
	env = append(env, "MINIO_SECRET_KEY=minio123")
	env = append(env, "AWS_ACCESS_KEY_ID=minio")
	env = append(env, "AWS_SECRET_KEY=minio123")

	minioServer := exec.Cmd{
		Path: "minio",
		Args: []string{
			"minio",
			"server",
			"--address",
			fmt.Sprintf("127.0.0.1:%d", backendPort),
			"./data",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	err = minioServer.Start()
	if err != nil {
		log.Printf("error starting minio %s: %v", sha, err)
		return
	}
	defer minioServer.Wait()
	defer minioServer.Process.Kill()

	<-time.After(5 * time.Second)

	minioGateway := exec.Cmd{
		Path: "minio",
		Args: []string{
			"minio",
			"gateway",
			"s3",
			fmt.Sprintf("http://127.0.0.1:%d", backendPort),
			"--address",
			fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	err = minioGateway.Start()
	if err != nil {
		log.Printf("error starting minio %s: %v", sha, err)
		return
	}
	defer minioGateway.Wait()
	defer minioGateway.Process.Kill()

	<-time.After(5 * time.Second)

	localRepo, err = git.PlainClone(filepath.Join("tmp", sha, "minio", "mint"), false, &git.CloneOptions{
		URL:      "https://github.com/minio/mint.git",
		Progress: f,
	})
	mintShaRef, err := localRepo.Head()
	if err != nil {
		log.Printf("error reading HEAD of minio/mint :%v", err)
		return
	}
	mintSha := mintShaRef.Hash().String()
	mintTestBuild := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"build",
			"-t",
			fmt.Sprintf("minio/mint:%s", mintSha),
			".",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "mint"),
		Stdout: f,
		//Stderr: f,
		Env: env,
	}
	err = mintTestBuild.Run()
	if err != nil {
		log.Printf("error building minio/mint: %v", err)
		return
	}
	defer mintTestBuild.Wait()
	defer mintTestBuild.Process.Kill()

	env = append(env, fmt.Sprintf("SERVER_ENDPOINT=127.0.0.1:%d", gatewayPort))
	env = append(env, "ENABLE_HTTPS=0")

	mintTests := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"run",
			"-e",
			fmt.Sprintf("SERVER_ENDPOINT=127.0.0.1:%d", gatewayPort),
			"-e",
			"ENABLE_HTTPS=0",
			"-e",
			"MINIO_ACCESS_KEY=minio",
			"-e",
			"MINIO_SECRET_KEY=minio123",
			"-e",
			"ACCESS_KEY=minio",
			"-e",
			"SECRET_KEY=minio123",
			"-e",
			"AWS_ACCESS_KEY_ID=minio",
			"-e",
			"AWS_SECRET_ACCESS_KEY=minio123",
			"--net=host",
			fmt.Sprintf("minio/mint:%s", mintSha),
		},
		Dir:    filepath.Join("tmp", sha, "minio", "mint"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	doneStatus = "failure"
	err = mintTests.Run()
	if err != nil {
		log.Printf("error running minio/mint:%s: %v", sha, err)
		doneStatus = "error"
		return
	}
	defer mintTests.Wait()
	defer mintTests.Process.Kill()
	doneStatus = "success"
	return
}

func (c *ciHandler) processPush(sha string) {
	var tmpPort uint32
	if err := c.updateStatus("minio", "minio", sha, github.String("pending")); err != nil {
		log.Printf("error updating status for minio/minio:%s %v", sha, err)
		return
	}
	doneStatus := "error"
	defer c.updateStatus("minio", "minio", sha, &doneStatus)

	f, err := os.OpenFile(filepath.Join("tmp", fmt.Sprintf("%s.log", sha)), os.O_RDWR|os.O_CREATE, 0664)
	if err != nil {
		log.Printf("error opening log file: %v", err)
		return
	}
	defer f.Close()
	log := log.New(f, "", 0)

	portLock.Lock()
	tmpPort = *port
	newPort := atomic.AddUint32(port, 2)
	if newPort >= 65000 {
		newPort = 36000
	}
	port = &newPort
	portLock.Unlock()

	backendPort := tmpPort
	gatewayPort := tmpPort + 1

	oauthClient := c.config.Client(oauth2.NoContext, c.token)
	client := github.NewClient(oauthClient)
	repo, _, err := client.Repositories.Get(context.Background(), "minio", "minio")
	if err != nil {
		log.Printf("error getting repository: %v", err)
		return
	}
	defer os.RemoveAll(filepath.Join("tmp", sha))
	cloneURL := repo.GetCloneURL()

	localRepo, err := git.PlainClone(filepath.Join("tmp", sha, "minio", "minio"), false, &git.CloneOptions{
		URL:      cloneURL,
		Progress: f,
	})
	if err != nil {
		log.Printf("error getting localRepo: %v", err)
		return
	}
	workTree, err := localRepo.Worktree()
	if err != nil {
		log.Printf("error getting worktree: %v", err)
		return
	}
	hash := plumbing.NewHash(sha)
	err = workTree.Checkout(&git.CheckoutOptions{
		Hash: hash,
	})
	if err != nil {
		log.Printf("error checking out rev: %s", sha)
		return
	}
	cwd, err := os.Getwd()
	if err != nil {
		log.Printf("error getting current working directory: %v", err)
		return
	}
	cmd := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"run",
			"-v",
			fmt.Sprintf("%s:/go/src/github.com/minio/minio", filepath.Join(cwd, "tmp", sha, "minio", "minio")),
			"golang:1.10",
			"go",
			"build",
			"-o",
			"/go/src/github.com/minio/minio/minio",
			"github.com/minio/minio",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
	}
	err = cmd.Run()
	if err != nil {
		log.Printf("error building minio/minio %s: %v", sha, err)
		return
	}

	env := os.Environ()
	env = append(env, "MINIO_ACCESS_KEY=minio")
	env = append(env, "MINIO_SECRET_KEY=minio123")
	env = append(env, "AWS_ACCESS_KEY_ID=minio")
	env = append(env, "AWS_SECRET_KEY=minio123")

	minioServer := exec.Cmd{
		Path: "minio",
		Args: []string{
			"minio",
			"server",
			"--address",
			fmt.Sprintf("127.0.0.1:%d", backendPort),
			"./data",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	err = minioServer.Start()
	if err != nil {
		log.Printf("error starting minio %s: %v", sha, err)
		return
	}
	defer minioServer.Process.Kill()

	<-time.After(5 * time.Second)

	minioGateway := exec.Cmd{
		Path: "minio",
		Args: []string{
			"minio",
			"gateway",
			"s3",
			fmt.Sprintf("http://127.0.0.1:%d", backendPort),
			"--address",
			fmt.Sprintf("127.0.0.1:%d", gatewayPort),
		},
		Dir:    filepath.Join("tmp", sha, "minio", "minio"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	err = minioGateway.Start()
	if err != nil {
		log.Printf("error starting minio %s: %v", sha, err)
		return
	}
	defer minioGateway.Process.Kill()

	<-time.After(5 * time.Second)

	localRepo, err = git.PlainClone(filepath.Join("tmp", sha, "minio", "mint"), false, &git.CloneOptions{
		URL:      "https://github.com/minio/mint.git",
		Progress: f,
	})
	mintShaRef, err := localRepo.Head()
	if err != nil {
		log.Printf("error reading HEAD of minio/mint :%v", err)
		return
	}
	mintSha := mintShaRef.Hash().String()
	mintTestBuild := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"build",
			"-t",
			fmt.Sprintf("minio/mint:%s", mintSha),
			".",
		},
		Dir:    filepath.Join("tmp", sha, "minio", "mint"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	err = mintTestBuild.Run()
	if err != nil {
		log.Printf("error building minio/mint: %v", err)
		return
	}
	defer mintTestBuild.Process.Kill()

	env = append(env, fmt.Sprintf("SERVER_ENDPOINT=127.0.0.1:%d", gatewayPort))
	env = append(env, "ENABLE_HTTPS=0")

	mintTests := exec.Cmd{
		Path: "/usr/bin/docker",
		Args: []string{
			"/usr/bin/docker",
			"run",
			"-e",
			fmt.Sprintf("SERVER_ENDPOINT=127.0.0.1:%d", gatewayPort),
			"-e",
			"ENABLE_HTTPS=0",
			"-e",
			"MINIO_ACCESS_KEY=minio",
			"-e",
			"MINIO_SECRET_KEY=minio123",
			"-e",
			"ACCESS_KEY=minio",
			"-e",
			"SECRET_KEY=minio123",
			"-e",
			"AWS_ACCESS_KEY_ID=minio",
			"-e",
			"AWS_SECRET_ACCESS_KEY=minio123",
			"--net=host",
			fmt.Sprintf("minio/mint:%s", mintSha),
		},
		Dir:    filepath.Join("tmp", sha, "minio", "mint"),
		Stdout: f,
		Stderr: f,
		Env:    env,
	}
	doneStatus = "failure"
	err = mintTests.Run()
	if err != nil {
		log.Printf("error running minio/mint:%s: %v", sha, err)
		doneStatus = "error"
		return
	}
	defer mintTests.Process.Kill()
	doneStatus = "success"
	return
}

func (c *ciHandler) exchangeToken(w http.ResponseWriter, r *http.Request) {
	responseState := r.FormValue("state")
	if state != responseState {
		return
	}

	code := r.FormValue("code")
	token, err := c.config.Exchange(oauth2.NoContext, code)
	if err != nil {
		log.Printf("oauth token exchange failed: %v", err)
		return
	}
	c.token = token
}

func (c *ciHandler) updateStatus(owner, repo, sha string, status *string) error {
	oauthClient := c.config.Client(oauth2.NoContext, c.token)
	client := github.NewClient(oauthClient)

	_, _, err := client.Repositories.CreateStatus(context.Background(), owner, repo, sha, &github.RepoStatus{
		State:       status,
		TargetURL:   github.String(fmt.Sprintf("%s/logs/%s", c.selfURL, sha)),
		Description: github.String("mint tests: minio as s3 backend"),
		Context:     github.String("minio-trusted/gateway-tests"),
	})
	return err
}
