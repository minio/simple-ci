package coord

import (
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
	"time"

	"github.com/golang/glog"
	"github.com/spf13/viper"
	"go.etcd.io/etcd/client"
)

type ConfigChanged string

func (cc ConfigChanged) Error() string {
	return "configuration changed"
}

func SyncServers(id string, store []string, servers []string) ([]string, int, error) {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")

	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		return nil, -1, err
	}

	kAPI := client.NewKeysAPI(c)
	peers := []string{}

	peerString := fmt.Sprintf("%s:%d", viper.GetString("ip"), viper.GetInt("port"))
	glog.V(8).Infof("peer-string: %s", peerString)
retry:
	simpleResp, err := kAPI.Get(context.Background(), filepath.Join(peersDir, "simple-ci_peers.json"), nil)
	if err != nil {
		if !client.IsKeyNotFound(err) {
			return nil, -1, err
		}
		glog.V(8).Infof("peers file not found")
		peers = append(peers, peerString)
		data, err := json.MarshalIndent(peers, "", " ")
		if err != nil {
			return nil, -1, err
		}
		_, err = kAPI.Set(context.Background(), filepath.Join(peersDir, "simple-ci_peers.json"), string(data), &client.SetOptions{
			PrevExist: client.PrevNoExist,
		})
		if err != nil {
			glog.Error(err)
			return nil, -1, err
		}
		goto retry
	}
	err = json.Unmarshal([]byte(simpleResp.Node.Value), &peers)
	if err != nil {
		return nil, -1, err
	}
	glog.V(8).Infof("existing peers file: %+v", peers)
	myId := 0
	space := map[string]bool{}
	for i, peer := range peers {
		if strings.Compare(peer, peerString) == 0 {
			myId = i + 1
		}
		space[peer] = true
	}

	glog.V(8).Infof("writing: %+v", filepath.Join(peersDir, peerString))
	_, err = kAPI.Set(context.Background(), filepath.Join(peersDir, peerString), "", &client.SetOptions{
		TTL: time.Second * 30,
	})
	if err != nil {
		return nil, -1, err
	}

	nodes := []string{}
	resp, err := kAPI.Get(context.Background(), peersDir, &client.GetOptions{
		Recursive: false,
		Sort:      true,
		Quorum:    true,
	})
	if err != nil {
		return nil, -1, err
	}
	for _, node := range resp.Node.Nodes {
		if strings.Index(node.Key, "simple-ci_peers.json") != -1 || strings.Index(node.Key, "simple-ci_configs") != -1 || strings.Index(node.Key, "simple-ci_tasks") != -1 {
			continue
		}
		nodes = append(nodes, strings.TrimLeft(node.Key[len(peersDir):], "/"))
	}

	for i, s := range nodes {
		if strings.Compare(s, peerString) == 0 {
			if myId != i+1 {
				err := updatePeers(kAPI, peersDir, nodes, peers)
				if err != nil {
					return nil, -1, err
				}
				return nil, -1, ConfigChanged("")
			}
		}
		if len(space) == 0 {
			err := updatePeers(kAPI, peersDir, nodes, peers)
			if err != nil {
				return nil, -1, err
			}
			return nil, -1, ConfigChanged("")
		}
		delete(space, s)
	}
	glog.V(8).Infof("debug: given servers: %+v scratch: %+v", servers, space)
	if len(servers) != 0 && len(space) != 0 {
		err := updatePeers(kAPI, peersDir, nodes, peers)
		if err != nil {
			return nil, -1, err
		}
		return nil, -1, ConfigChanged("")
	}
	if len(servers) != 0 {
		if len(servers) != len(nodes) {
			err := updatePeers(kAPI, peersDir, nodes, peers)
			if err != nil {
				return nil, -1, err
			}
			return nil, -1, ConfigChanged("")
		}

		for _, s := range servers {
			space[s] = true
		}
		for _, n := range nodes {
			if _, ok := space[n]; !ok {
				err := updatePeers(kAPI, peersDir, nodes, peers)
				if err != nil {
					return nil, -1, err
				}
				return nil, -1, ConfigChanged("")
			}
			delete(space, n)
		}

		if len(space) != 0 {
			err := updatePeers(kAPI, peersDir, nodes, peers)
			if err != nil {
				return nil, -1, err
			}
			return nil, -1, ConfigChanged("")
		}
	}
	servers = nodes
	glog.V(8).Infof("servers=%+v", nodes)
	return servers, myId, nil
}

func updatePeers(kAPI client.KeysAPI, peersDir string, peers, prev []string) error {
	data, err := json.MarshalIndent(peers, "", " ")
	if err != nil {
		return err
	}

	oldData, err := json.MarshalIndent(prev, "", " ")
	if err != nil {
		return err
	}
	glog.V(8).Infof("writing peers file with data:%s", string(data))
	_, err = kAPI.Set(context.Background(), filepath.Join(peersDir, "simple-ci_peers.json"), string(data), &client.SetOptions{
		PrevValue: string(oldData),
	})
	if err != nil {
		return err
	}
	return nil
}

func Sync(id string, myId int, store []string) ([]byte, error) {
	peersDir := strings.TrimRight(id, "/")
	peersDir = strings.TrimRight(peersDir, "simple-ci")

	cfg := client.Config{
		Endpoints: store,
		Transport: client.DefaultTransport,
	}

	c, err := client.New(cfg)
	if err != nil {
		return nil, err
	}

	kAPI := client.NewKeysAPI(c)

	notFound := false
	node := []byte{}
	simpleResp, err := kAPI.Get(context.Background(), filepath.Join(id, "simple-ci.json", fmt.Sprintf("%d", myId)), nil)
	if err != nil {
		if !client.IsKeyNotFound(err) {
			return nil, err
		}
		notFound = true
	}

	if notFound {
		data, err := json.MarshalIndent(struct{}{}, "", " ")
		if err != nil {
			return nil, err
		}

		_, err = kAPI.Set(context.Background(), filepath.Join(id, "simple-ci.json", fmt.Sprintf("%d", 0)), string(data), nil)
		if err != nil {
			return nil, err
		}
		node = data
	} else {
		node = []byte(simpleResp.Node.Value)
	}
	return node, nil
}
