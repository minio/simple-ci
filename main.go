package main

import (
	"github.com/golang/glog"
	"github.com/wlan0/simple-ci/cmd"
)

func main() {
	if err := cmd.RootCmd.Execute(); err != nil {
		glog.Fatal(err)
	}
}
