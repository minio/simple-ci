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

package components

import (
	"fmt"

	_ "github.com/gopherjs/gopherjs/js"
	"github.com/gopherjs/vecty"
	"github.com/gopherjs/vecty/elem"
	_ "honnef.co/go/js/dom"
)

type SimpleCI struct {
	lineCh  chan string
	Lines   []vecty.MarkupOrChild
	Footer  *Footer
	LineNum string
	vecty.Core
}

func (s *SimpleCI) Render() vecty.ComponentOrHTML {
	if s.Footer == nil {
		s.Footer = &Footer{}
	}
	s.Footer.TotalLines = len(s.Lines)

	return elem.Body(
		styler().
			bgcolor(DarkGray).
			fontFamily(SourceCodePro).
			fontSize("small").
			color("#d8d8d8").
			marginBottom("30px").Render(),
		elem.Paragraph(
			append(
				s.Lines,
				styler().lineHeight("1.5").Render(),
			)...,
		),
		s.Footer,
	)
}

func (s *SimpleCI) SetLineCh(lines chan string) {
	s.lineCh = lines

	go func() {
		i := 0
		for line := range lines {
			i++
			focus := false
			if fmt.Sprintf("L%d", i) == s.LineNum {
				focus = true
			}
			s.Lines = append(s.Lines, &Line{
				Number: i,
				Line:   line,
				focus:  focus,
			})
			vecty.Rerender(s)
		}
	}()
}
