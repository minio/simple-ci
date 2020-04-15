/*
 * Minio Cloud Storage, (C) 2019 Minio, Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package ci

import (
	"context"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"math/rand"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/google/go-github/v21/github"
	"github.com/gorilla/websocket"
	"github.com/minio/simple-ci/pkg/minlog"
	"github.com/minio/simple-ci/pkg/task"
	"github.com/spf13/viper"
	"golang.org/x/oauth2"
	ghub "golang.org/x/oauth2/github"
	"gopkg.in/src-d/go-git.v4"
	"gopkg.in/src-d/go-git.v4/plumbing"
)

var upgrader = websocket.Upgrader{}

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
	(w).Header().Set("Access-Control-Allow-Origin", "*")
	(w).Header().Set("Access-Control-Allow-Methods", "POST, GET, OPTIONS, PUT, DELETE")
	(w).Header().Set("Access-Control-Allow-Headers", "Accept, Content-Type, Content-Length, Accept-Encoding, X-CSRF-Token, Authorization")

	if strings.HasPrefix(r.URL.Path, "/view") {
		file := strings.Trim(r.URL.Path[5:], "/")
		if file == "" {
			file = "index.html"
		}
		b, e := ioutil.ReadFile(filepath.Join("ui", file))
		if e != nil {
			b, e = ioutil.ReadFile(filepath.Join("ui", "index.html"))
			if e != nil {
				w.WriteHeader(500)
				w.Write([]byte(e.Error()))
				return
			}
		}
		w.Write(b)
		return
	}

	if r.URL.Path == "/login" {
		if c.token != nil {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		url := c.config.AuthCodeURL(state, oauth2.AccessTypeOnline)
		http.Redirect(w, r, url, http.StatusTemporaryRedirect)
		return
	}

	if strings.HasPrefix(r.URL.Path, "/ws") {
		tx, err := upgrader.Upgrade(w, r, nil)
		if err != nil {
			log.Print("upgrade:", err)
			return
		}
		defer tx.Close()

		vals := strings.Split(r.URL.Path, "/")
		sha := vals[len(vals)-1]

		u := url.URL{Scheme: "ws", Host: viper.GetString("log-backend"), Path: fmt.Sprintf("/read/%s.log", sha)}
		log.Printf("connecting to %s", u.String())

		rx, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
		if err != nil {
			log.Printf("connecting to %s, failed %s", u.String(), err)
			return
		}
		defer rx.Close()
		if err == nil {
			done := make(chan bool, 1)
			errChan := make(chan error, 1)
			go func() {
				defer close(done)
				for {
					_, message, err := rx.ReadMessage()
					if err != nil {
						if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseAbnormalClosure) {
							errChan <- err
							log.Println("read:", err)
						}
						break
					}
					err = tx.WriteMessage(websocket.TextMessage, message)
					if err != nil {
						log.Println("write:", err)
						return
					}
				}
			}()

			select {
			case <-done:
				return
			case <-errChan:
				log.Printf("logger ws server could not fetch data, trying minio backend")
			}

		}
		return
	}

	if strings.HasPrefix(r.URL.Path, "/build/") {
		vals := strings.Split(r.URL.Path, "/build/")
		if len(vals) != 2 {
			log.Printf("error getting owner/repo/sha from url")
			w.WriteHeader(http.StatusBadRequest)
			return
		}

		values := strings.Split(vals[1], "/")
		if len(values) != 3 {
			log.Printf("error getting owner/repo/sha from url")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		owner := values[0]
		repo := values[1]
		prStr := values[2]

		pr, err := strconv.Atoi(prStr)
		if err != nil {
			w.Write([]byte(err.Error()))
			w.WriteHeader(http.StatusInternalServerError)
			return
		}

		go func() {
			t := &task.Task{
				Name:   fmt.Sprintf("build-%s", prStr),
				Owner:  owner,
				Repo:   repo,
				Pr:     pr,
				Config: c.config,
				Token:  c.token,
			}
			if err := task.AddTask(c.id, c.store, t); err != nil {
				w.Write([]byte(err.Error()))
				w.WriteHeader(http.StatusInternalServerError)
				return
			}
			w.WriteHeader(http.StatusOK)
		}()

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

func processBuild(id string, store []string, t *task.Task) {
	token := t.Token
	if token == nil {
		var err error
		token, err = task.GetToken(id, store)
		if err != nil {
			log.Printf("error getting token: %v", err)
			return
		}
	}

	config := t.Config
	oauthClient := config.Client(oauth2.NoContext, token)
	oauthClient.Jar = &gitCookieJar{}
	client := github.NewClient(oauthClient)

	owner := t.Owner
	repo := t.Repo

	pr, _, err := client.PullRequests.Get(context.Background(), owner, repo, t.Pr)
	if err != nil {
		log.Printf("error getting PR: %v", err)
		return
	}
	head := pr.GetHead()
	sha := *(head.SHA)

	nameParts := strings.Split(*head.Repo.FullName, "/")

	log.Printf("processing pull_request %s/%s:%s fullname:%s", owner, repo, sha, *head.Repo.FullName)
	branchRef := plumbing.NewBranchReferenceName(*head.Ref)

	f := minlog.New(fmt.Sprintf("%s.log", sha))
	defer f.Close()

	log := log.New(f, "", 0)
	if err := updateStatus(config, token, owner, repo, sha, github.String("pending")); err != nil {
		log.Printf("error updating status for %s%s:%s %v", owner, repo, sha, err)
		return
	}

	doneStatus := "error"
	defer updateStatus(config, token, owner, repo, sha, &doneStatus)

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

func processPullRequest(id string, store []string, t *task.Task) {
	token := t.Token
	if token == nil {
		var err error
		token, err = task.GetToken(id, store)
		if err != nil {
			log.Printf("error getting token: %v", err)
			return
		}
	}

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

	f := minlog.New(fmt.Sprintf("%s.log", sha))
	defer f.Close()

	log := log.New(f, "", 0)
	if err := updateStatus(config, token, owner, repo, sha, github.String("pending")); err != nil {
		log.Printf("error updating status for %s%s:%s %v", owner, repo, sha, err)
		return
	}

	doneStatus := "error"
	defer updateStatus(config, token, owner, repo, sha, &doneStatus)

	oauthClient := config.Client(oauth2.NoContext, token)
	oauthClient.Jar = &gitCookieJar{}
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

func processPush(id string, store []string, t *task.Task) {
	token := t.Token
	if token == nil {
		var err error
		token, err = task.GetToken(id, store)
		if err != nil {
			log.Printf("error getting token: %v", err)
			return
		}
	}

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

	log.Printf("processing push %s/%s:%s fullname:%s", owner, repo, sha, *(pushEvent.GetRepo().FullName))
	f := minlog.New(fmt.Sprintf("%s.log", sha))
	defer f.Close()
	log := log.New(f, "", 0)

	oauthClient := config.Client(oauth2.NoContext, token)
	oauthClient.Jar = &gitCookieJar{}
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
			"--rm",
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

	if err := task.SetToken(c.id, c.store, token); err != nil {
		log.Printf("error saving token to etcd: %v", err)
	}
}

func updateStatus(config *oauth2.Config, token *oauth2.Token, owner, repo, sha string, status *string) error {
	oauthClient := config.Client(oauth2.NoContext, token)
	client := github.NewClient(oauthClient)

	_, _, err := client.Repositories.CreateStatus(context.Background(), owner, repo, sha, &github.RepoStatus{
		State:       status,
		TargetURL:   github.String(fmt.Sprintf("%s/view/%s", viper.GetString("github-endpoint"), sha)),
		Description: github.String(viper.GetString("description")),
		Context:     github.String(viper.GetString("app-name")),
	})
	return err
}
