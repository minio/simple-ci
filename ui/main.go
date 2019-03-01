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

package main

import (
	"bufio"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/gopherjs/gopherjs/js"
	"github.com/gopherjs/vecty"
	"github.com/gopherjs/websocket"
	"github.com/wlan0/simple-ci/ui/pkg/components"
)

var items = []vecty.MarkupOrChild{}

func main() {
	url := ""
	doc := js.Global.Get("document")
	if doc.Get("readyState").String() == "loading" {
		url = js.Global.Get("location").String()
	}

	loadUrl := strings.Replace(url, "view", "ws", -1)
	loadUrl = strings.Replace(loadUrl, "http", "ws", -1)

	loadUrl = strings.Split(loadUrl, "#")[0]

	c, err := websocket.Dial(loadUrl)
	if err != nil {
		fmt.Printf("error opening ci logs %v", err)
		runtime.Goexit()
	}
	defer c.Close()

	lineNum := ""
	urlLineNum := strings.Split(url, "#")
	if len(urlLineNum) > 1 {
		lineNum = urlLineNum[1]
	}
	lineCh := make(chan string, 100)

	m := &components.SimpleCI{
		LineNum: lineNum,
	}
	m.SetLineCh(lineCh)

	vecty.SetTitle("Simple CI")
	vecty.RenderBody(m)

	done := make(chan bool, 1)
	errChan := make(chan error, 1)

	b := bufio.NewReader(c)

	go func() {
		defer close(done)
		for {
			message, err := b.ReadString('\n')
			if err != nil {
				if err != io.EOF {
					errChan <- err
					fmt.Printf("read err: %v", err)
				}
				lineCh <- string(message)
				fmt.Println("done")
				break
			}
			lineCh <- string(message)
		}
	}()

	select {
	case <-done:
		return
	case <-errChan:
		fmt.Printf("err: %v", err)
	}
}

// DOMReady fires the provided function when the dom is ready.
func DOMReady(fn func()) {
	if callReady(fn) {
		return
	}

	doc := js.Global.Get("document")
	if doc.Get("addEventListener") != js.Undefined {

		// first choice is DOMContentLoaded event
		doc.Call("addEventListener", "DOMContentLoaded", func() { callReady(fn) }, false)
		// backup is window load event
		js.Global.Call("addEventListener", "load", func() { callReady(fn) }, false)

	} else {

		// Must be IE
		doc.Call("attachEvent", "onreadystatechange", callReady)

		js.Global.Call("attachEvent", "onload", func() {
			callReady(fn)
		})
	}
}

// callReady returns true/false if the document had reached a ready state.
func callReady(fn func()) bool {
	doc := js.Global.Get("document")
	if doc.Get("readyState").String() == "complete" {
		go fn()
		return true
	}

	return false
}
