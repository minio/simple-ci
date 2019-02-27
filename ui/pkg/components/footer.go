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
