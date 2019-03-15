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

package minlog

import (
	"fmt"
	"log"
	"net/url"
	"strings"

	"github.com/golang/glog"
	"github.com/gorilla/websocket"
	"github.com/spf13/viper"
)

type MinLog struct {
	log    string
	bucket string
	file   string
	c      *websocket.Conn
}

func New(bucket, file string) *MinLog {
	u := url.URL{Scheme: "ws", Host: viper.GetString("log-backend"), Path: fmt.Sprintf("/write/%s", file)}
	log.Printf("connecting to %s", u.String())

	c, _, err := websocket.DefaultDialer.Dial(u.String(), nil)
	if err != nil {
		glog.Errorf("could not connect to logger dial: %v", err)
	}

	return &MinLog{
		bucket: bucket,
		file:   file,
		c:      c,
	}
}

func (m *MinLog) Write(data []byte) (int, error) {
	err := m.c.WriteMessage(websocket.TextMessage, data)
	if err != nil {
		log.Println("write:", err)
		return -1, err
	}

	return len(data), nil
}

func (m *MinLog) Read(p []byte) (int, error) {
	return strings.NewReader(m.log).Read(p)
}

func (m *MinLog) Close() error {
	return m.c.Close()
}
