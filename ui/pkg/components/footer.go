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
	"time"

	"github.com/gopherjs/vecty"
	"github.com/gopherjs/vecty/elem"
)

type Footer struct {
	CurrentLine int
	TotalLines  int
	ElapsedTime time.Time
	vecty.Core
}

func (f *Footer) Render() vecty.ComponentOrHTML {
	return elem.Div(
		styler().
			position("fixed").
			left("0").
			bottom("0").
			width("100%").
			bold().
			bgcolor("#00cc74").
			fontFamily(SourceCodePro).
			padding("4px").
			color(DarkGray).Render(),
		vecty.Text(fmt.Sprintf("Total %d                                   ", f.TotalLines)),
	)
}
