package task

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/google/go-github/v21/github"
	"go.etcd.io/etcd/client"
	"golang.org/x/oauth2"
)

type Task struct {
	Name             string
	PullRequestEvent *github.PullRequestEvent
	PushEvent        *github.PushEvent
	Token            *oauth2.Token
	Config           *oauth2.Config
}

func (t *Task) Refresh(id string, store []string) error {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tasksDir := filepath.Join(peersDir, "simple-ci_tasks")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		return err
	}

	kAPI := client.NewKeysAPI(c)
	_, err = kAPI.Set(context.Background(), filepath.Join(tasksDir, fmt.Sprintf("%s.lock", t.Name)), "", &client.SetOptions{
		Refresh: true,
		TTL:     30 * time.Second,
	})
	return err

}

func GetTask(id string, store []string) (*Task, error) {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tasksDir := filepath.Join(peersDir, "simple-ci_tasks")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	kAPI := client.NewKeysAPI(c)

retry:
	resp, err := kAPI.Get(context.Background(), tasksDir, &client.GetOptions{
		Recursive: false,
		Sort:      true,
		Quorum:    true,
	})
	if err != nil {
		glog.Errorf("error getting key: %s: %v", tasksDir, err)
		return nil, err
	}

	for _, task := range resp.Node.Nodes {
		key := task.Key
		if task.Value == "" {
			continue
		}
		if _, err := kAPI.Set(context.Background(), fmt.Sprintf("%s.lock", key), "", &client.SetOptions{
			PrevExist: client.PrevNoExist,
			TTL:       30 * time.Second,
		}); err != nil {
			if eErr, ok := err.(client.Error); !ok {
				glog.Error("invalid error type: %v", err)
				return nil, err
			} else if eErr.Code == client.ErrorCodeNodeExist {
				continue
			}
			glog.Errorf("error creating lock for task: %s: %v", key, err)
			return nil, err
		} else {
			t := &Task{}
			glog.V(8).Infof("get task: obtained lock for %s: %v", key, task.Value)
			if err := json.Unmarshal([]byte(task.Value), &t); err != nil {
				glog.Errorf("invalid task struct for task: %s: %v", key, err)
				return nil, err
			}
			return t, nil
		}
	}
	<-time.After(5 * time.Second)
	goto retry
	panic("unreachable")
	return nil, nil
}

func AddTask(id string, store []string, t *Task) error {
	glog.Infof("adding task: %s", id)
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tasksDir := filepath.Join(peersDir, "simple-ci_tasks")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		glog.Errorf("error adding task: could not create etcd client: %v", err)
		return err
	}

	kAPI := client.NewKeysAPI(c)

	taskVal, err := json.MarshalIndent(t, "", " ")
	if err != nil {
		glog.Errorf("error adding task: %s: %v", t.Name, err)
		return err
	}
retry:
	if _, err := kAPI.Set(context.Background(), filepath.Join(tasksDir, t.Name), string(taskVal), &client.SetOptions{
		PrevExist: client.PrevNoExist,
	}); err != nil {
		if eErr, ok := err.(client.Error); !ok {
			glog.Error("invalid error type: %v", err)
			return err
		} else if eErr.Code == client.ErrorCodeNodeExist {
			glog.Infof("node already exists, retying: errCode: %#v", eErr)
			<-time.After(30 * time.Second)
			goto retry
		}
		glog.Errorf("error adding task: %s: %v", t.Name, err)

		return err
	}
	return nil
}

func ClearTask(id string, store []string, t *Task) error {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tasksDir := filepath.Join(peersDir, "simple-ci_tasks")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		glog.Errorf("error clearing task: could not create etcd client: %v", err)
		return err
	}

	kAPI := client.NewKeysAPI(c)
	if _, err := kAPI.Delete(context.Background(), filepath.Join(tasksDir, t.Name), &client.DeleteOptions{}); err != nil {
		glog.Errorf("error clearing task: %s: %v", t.Name, err)
		return err
	}
	return nil
}

func SetToken(id string, store []string, t *oauth2.Token) error {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tokenFile := filepath.Join(peersDir, "simple-ci_token")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		glog.Errorf("error writing token: could not create etcd client: %v", err)
		return err
	}

	tokenVal, err := json.MarshalIndent(t, "", " ")
	if err != nil {
		glog.Errorf("error marshalling token: %s: %v", t, err)
		return err
	}
	kAPI := client.NewKeysAPI(c)
	_, err = kAPI.Set(context.Background(), tokenFile, string(tokenVal), &client.SetOptions{
		PrevExist: client.PrevNoExist,
	})
	return err
}

func GetToken(id string, store []string) (*oauth2.Token, error) {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")
	tokenFile := filepath.Join(peersDir, "simple-ci_token")
	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		glog.Errorf("error getting token: could not create etcd client: %v", err)
		return nil, err
	}

	kAPI := client.NewKeysAPI(c)
	resp, err := kAPI.Get(context.Background(), tokenFile, nil)
	if err != nil {
		return nil, err
	}

	token := &oauth2.Token{}
	if err := json.Unmarshal([]byte(resp.Node.Value), token); err != nil {
		return nil, err
	}

	return token, nil
}
