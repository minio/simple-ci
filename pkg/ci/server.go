package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/go-github/v21/github"
	"github.com/minio/minio-go"
	"github.com/spf13/viper"
	"github.com/wlan0/simple-ci/pkg/minlog"
	"github.com/wlan0/simple-ci/pkg/task"
	"golang.org/x/oauth2"
	ghub "golang.org/x/oauth2/github"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
)

var state string

func init() {
	state = fmt.Sprintf("%v", rand.Uint64())
}

func startCIServer(id string, store []string) error {
	addr := fmt.Sprintf("%s:%d", viper.GetString("ip"), viper.GetInt("port"))
	selfURL := viper.GetString("github-endpoint")
	webhookSecret := viper.GetString("webhook-secret")
	githubID := viper.GetString("github-id")
	githubSecret := viper.GetString("github-secret")
	token := viper.GetString("token")
	//TBD: token type and expiry flags

	conf := &oauth2.Config{
		ClientID:     githubID,
		ClientSecret: githubSecret,
		Scopes: []string{
			"repo",
		},
		Endpoint:    ghub.Endpoint,
		RedirectURL: selfURL,
	}

	var t *oauth2.Token
	if token != "" {
		t = &oauth2.Token{
			AccessToken: token,
			TokenType:   "bearer",
		}
	}

	s := &http.Server{
		Addr: addr,
		Handler: &ciHandler{
			config:        conf,
			selfURL:       selfURL,
			webhookSecret: []byte(webhookSecret),
			id:            id,
			store:         store,
			token:         t,
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
	id            string
	store         []string
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

		mc, err := minio.New(viper.GetString("s3-endpoint"), viper.GetString("s3-access-key"), viper.GetString("s3-secret"), false)
		if err != nil {
			log.Printf("could not connect with s3: %v", err)
			return
		}
		id := viper.GetString("id")
		bucket := strings.Trim(strings.Replace(id, "/", "-", -1), "-")
		obj, err := mc.GetObject(bucket, fmt.Sprintf("%s.log", sha), minio.GetObjectOptions{})
		if err != nil {
			log.Printf("error getting logs from s3: %v", err)
			return
		}

		logs, err := ioutil.ReadAll(obj)
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
			go func() {
				t := &task.Task{
					Name:      *(event.(*github.PushEvent).After),
					PushEvent: event.(*github.PushEvent),
					Token:     c.token,
					Config:    c.config,
				}
				if err := task.AddTask(c.id, c.store, t); err != nil {
					w.Write([]byte(err.Error()))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}()
			return
		}
		if github.WebHookType(r) == "pull_request" {
			go func() {
				t := &task.Task{
					Name:             *(event.(*github.PullRequestEvent).GetPullRequest().GetHead().SHA),
					PullRequestEvent: event.(*github.PullRequestEvent),
					Token:            c.token,
					Config:           c.config,
				}
				if err := task.AddTask(c.id, c.store, t); err != nil {
					w.Write([]byte(err.Error()))
					w.WriteHeader(http.StatusInternalServerError)
					return
				}
			}()
			return
		}
		log.Printf("unknown webhook type %s", github.WebHookType(r))
		return
	}
	c.exchangeToken(w, r)
}

func processPullRequest(t *task.Task) {
	token := t.Token
	config := t.Config
	pullRequestEvent := t.PullRequestEvent
	if *(pullRequestEvent.Action) != "opened" && *(pullRequestEvent.Action) != "synchronize" {
		log.Printf("ignoring pull_request event: %s", *pullRequestEvent.Action)
		return
	}
	pr := pullRequestEvent.GetPullRequest()
	head := pr.GetHead()
	sha := *(head.SHA)

	nameParts := strings.Split(*head.Repo.FullName, "/")
	ownerObj := head.Repo.Owner
	if ownerObj == nil {
		ownerObj = pullRequestEvent.Repo.Owner
	}
	owner := *ownerObj.Login
	if org := pullRequestEvent.Organization; org != nil {
		owner = *org.Login
	}
	repo := nameParts[1]

	log.Printf("processing pull_request %s/%s:%s fullname:%s", owner, repo, sha, *head.Repo.FullName)
	branchRef := plumbing.NewBranchReferenceName(*head.Ref)

	s3URL := viper.GetString("s3-endpoint")
	accessKey := viper.GetString("s3-access-key")
	secretKey := viper.GetString("s3-secret")
	mc, err := minio.New(s3URL, accessKey, secretKey, false)
	if err != nil {
		log.Printf("could not connect with s3:%s: user: %s pass: %s err:%v", s3URL, accessKey, secretKey, err)
		return
	}
	id := viper.GetString("id")
	bucket := strings.Trim(strings.Replace(id, "/", "-", -1), "-")
	err = mc.MakeBucket(bucket, "")
	if err != nil {
		if err, ok := err.(minio.ErrorResponse); ok {
			if err.Code != "BucketAlreadyOwnedByYou" {
				log.Printf("error creating bucket: %s err:%v", bucket, err)
				return

			}
		} else {
			log.Printf("error creating bucket: %s err:%v", bucket, err)
			return
		}
	}

	if obj, err := mc.GetObject(bucket, fmt.Sprintf("%s.log", sha), minio.GetObjectOptions{}); err == nil {
		if _, err := obj.Stat(); err == nil {
			log.Printf("commit already processed: %s/%s.log", bucket, sha)
			return
		}
	}

	f := minlog.New(mc, bucket, fmt.Sprintf("%s.log", sha))
	log := log.New(f, "", 0)
	if err := updateStatus(config, token, owner, repo, sha, github.String("pending")); err != nil {
		log.Printf("error updating status for %s%s:%s %v", owner, repo, sha, err)
		return
	}

	doneStatus := "error"
	defer updateStatus(config, token, owner, repo, sha, &doneStatus)

	oauthClient := config.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	repoObj, _, err := client.Repositories.Get(context.Background(), nameParts[0], repo)
	if err != nil {
		log.Printf("error getting repository: %v", err)
		return
	}
	cloneURL := repoObj.GetCloneURL()

	localRepo, err := git.PlainClone(filepath.Join("tmp", sha, owner, repo), false, &git.CloneOptions{
		URL:           cloneURL,
		Progress:      f,
		ReferenceName: branchRef,
	})
	if err != nil {
		log.Printf("error getting localRepo: %v", err)
		return
	}
	defer os.RemoveAll(filepath.Join("tmp", sha))
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
			"build",
			"--rm",
			"-t",
			fmt.Sprintf("%s/%s:%s", owner, repo, sha),
			".",
		},
		Dir:    filepath.Join(cwd, "tmp", sha, owner, repo),
		Stdout: f,
		Stderr: f,
	}
	err = cmd.Run()
	if err != nil {
		log.Printf("error running ci task for %s/%s:%s: %v", owner, repo, sha, err)
		doneStatus = "failure"
		return
	}
	doneStatus = "success"
	return
}

func processPush(t *task.Task) {
	token := t.Token
	config := t.Config
	pushEvent := t.PushEvent
	repo := *(pushEvent.GetRepo().Name)
	owner := *(pushEvent.GetRepo().Owner.Login)
	sha := pushEvent.GetAfter()

	if err := updateStatus(config, token, owner, repo, sha, github.String("pending")); err != nil {
		log.Printf("error updating status for %s%s:%s %v", owner, repo, sha, err)
		return
	}
	doneStatus := "error"
	defer updateStatus(config, token, owner, repo, sha, &doneStatus)

	mc, err := minio.New(viper.GetString("s3-endpoint"), viper.GetString("s3-access-key"), viper.GetString("s3-secret"), false)
	if err != nil {
		log.Printf("could not connect with s3: %v", err)
		return
	}
	id := viper.GetString("id")
	bucket := strings.Trim(strings.Replace(id, "/", "-", -1), "-")
	err = mc.MakeBucket(bucket, "")
	if err != nil {
		if err, ok := err.(minio.ErrorResponse); ok {
			if err.Code != "BucketAlreadyOwnedByYou" {
				log.Printf("error creating bucket: %s err:%v", bucket, err)
				return

			}
		} else {
			log.Printf("error creating bucket: %s err:%v", bucket, err)
			return
		}
	}

	if obj, err := mc.GetObject(bucket, fmt.Sprintf("%s.log", sha), minio.GetObjectOptions{}); err == nil {
		if _, err := obj.Stat(); err == nil {
			log.Printf("commit already processed: %s/%s.log", bucket, sha)
			return
		}
	}

	log.Printf("processing push %s/%s:%s fullname:%s", owner, repo, sha, *(pushEvent.GetRepo().FullName))
	f := minlog.New(mc, bucket, fmt.Sprintf("%s.log", sha))
	log := log.New(f, "", 0)

	oauthClient := config.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)
	repoObj, _, err := client.Repositories.Get(context.Background(), owner, repo)
	if err != nil {
		log.Printf("error getting repository: %v", err)
		return
	}
	cloneURL := repoObj.GetCloneURL()

	localRepo, err := git.PlainClone(filepath.Join("tmp", sha, owner, repo), false, &git.CloneOptions{
		URL:      cloneURL,
		Progress: f,
	})
	if err != nil {
		log.Printf("error getting localRepo: %v", err)
		return
	}
	defer os.RemoveAll(filepath.Join("tmp", sha))
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
			"build",
			"-f",
			"Dockerfile.simpleci",
			"-t",
			fmt.Sprintf("%s/%s:%s", owner, repo, sha),
			".",
		},
		Dir:    filepath.Join(cwd, "tmp", sha, owner, repo),
		Stdout: f,
		Stderr: f,
	}
	err = cmd.Run()
	if err != nil {
		log.Printf("error running ci task for %s/%s:%s: %v", owner, repo, sha, err)
		doneStatus = "failure"
		return
	}
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
	t, err := json.MarshalIndent(token, "", " ")
	if err != nil {
		log.Printf("token obtained, but could not save to filesystem: %v", err)
		return
	}
	if err := ioutil.WriteFile("token", t, 0664); err != nil {
		log.Printf("error saving token to file: %v", err)
	}
}

func updateStatus(config *oauth2.Config, token *oauth2.Token, owner, repo, sha string, status *string) error {
	oauthClient := config.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)

	_, _, err := client.Repositories.CreateStatus(context.Background(), owner, repo, sha, &github.RepoStatus{
		State:       status,
		TargetURL:   github.String(fmt.Sprintf("%s/logs/%s", viper.GetString("github-endpoint"), sha)),
		Description: github.String(viper.GetString("description")),
		Context:     github.String(viper.GetString("app-name")),
	})
	return err
}
