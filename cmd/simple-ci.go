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

package cmd

import (
	"flag"
	"strings"

	"github.com/minio/simple-ci/pkg/ci"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	_ "github.com/golang/glog"
)

var RootCmd = &cobra.Command{
	Use:   "simple-ci",
	Short: "easy to setup, highly scalable ci system",
	RunE: func(c *cobra.Command, args []string) error {
		return ci.Run()
	},
	SilenceErrors: true,
	SilenceUsage:  true,
}

func init() {
	viper.AutomaticEnv()
	replacer := strings.NewReplacer("-", "_")
	viper.SetEnvKeyReplacer(replacer)

	RootCmd.Flags().StringSlice("store", []string{}, "list of etcd nodes")
	RootCmd.Flags().String("id", "", "unique id of the simple-ci cluster")
	RootCmd.Flags().String("ip", "", "ip address of the simple-ci server")
	RootCmd.Flags().Int("port", 8888, "port at which simple-ci server listens")

	RootCmd.Flags().String("github-endpoint", "", "callback endpoint of the simple-ci server")
	RootCmd.Flags().String("github-id", "", "github client id of the simple-ci server")
	RootCmd.Flags().String("github-secret", "", "github secret of the simple-ci server")
	RootCmd.Flags().String("webhook-secret", "", "webhook secret of the simple-ci github application")

	RootCmd.Flags().String("log-backend", "", "backend to push logs to")

	RootCmd.Flags().String("app-name", "simple-ci", "name of the app to show in github status")
	RootCmd.Flags().String("description", "", "short message to show in the github status")

	RootCmd.Flags().String("token", "", "the access token (bearer) for the github app")

	// parse the go default flagset to get flags for glog and other packages in future
	RootCmd.Flags().AddGoFlagSet(flag.CommandLine)

	// defaulting this to true so that logs are printed to console
	flag.Set("logtostderr", "true")

	//suppress the incorrect prefix in glog output
	flag.CommandLine.Parse([]string{})

	viper.BindPFlags(RootCmd.Flags())
}
