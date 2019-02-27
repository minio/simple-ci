package ci

import (
	"errors"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/viper"
	"github.com/wlan0/simple-ci/pkg/coord"
	"github.com/wlan0/simple-ci/pkg/task"
)

func Run() error {
	id := viper.GetString("id")
	storeInterface := viper.Get("store")
	ip := viper.GetString("ip")
	s3Endpoint := viper.GetString("s3-endpoint")
	glog.Infof("starting with ip: %s", ip)
	store, ok := storeInterface.([]string)
	if !ok {
		glog.Errorf("invalid config")
		return errors.New("invalid type for --store; should be string")
	}
	if len(id) == 0 {
		glog.Errorf("invalid config")
		return errors.New("--id cannot be empty")
	}

	if len(store) == 0 {
		glog.Errorf("invalid config")
		return errors.New("--store cannot be empty")
	}

	if len(ip) == 0 {
		glog.Errorf("invalid config")
		return errors.New("--ip cannot be empty")
	}

	if len(s3Endpoint) == 0 {
		glog.Errorf("invalid config")
		return errors.New("--s3-endpoint cannot be empty")
	}

	servers, myId, err := coord.SyncServers(id, store, []string{})
	if err != nil {
		glog.Errorf("could not coordinate with peers")
		return err
	}

	glog.Infof("myId: %d servers: %+v", myId, servers)

	errChan := make(chan error, 1)
	taskLoop := func() error {
		for {
			if t, err := task.GetTask(id, store); err != nil {
				glog.Errorf("error getting task: %v", err)
			} else {
				go processTask(id, store, t, errChan)
			}
			<-time.After(10 * time.Second)
		}
	}
	go taskLoop()

	go func() {
		for err := range errChan {
			glog.Errorf("err from task loop: %v", err)
		}
	}()

	return startCIServer(id, store)
}

func processTask(id string, store []string, t *task.Task, errChan chan error) {
	glog.Infof("processing task: %s", t.Name)
	cancel := make(chan bool, 1)
	if err := t.Refresh(id, store); err != nil {
		errChan <- err
		return
	}
	go func() {
		for {
			select {
			case <-cancel:
				return
			case <-time.After(15 * time.Second):
				if err := t.Refresh(id, store); err != nil {
					errChan <- err
					return
				}
			}
		}
	}()
	if t.PullRequestEvent != nil {
		processPullRequest(id, store, t)
	}
	if t.PushEvent != nil {
		processPush(id, store, t)
	}
	glog.Infof("clearing task: %s", t.Name)
	if err := task.ClearTask(id, store, t); err != nil {
		glog.Errorf("error clearing task: %s", t.Name)
		errChan <- err
	}
	cancel <- true
}
