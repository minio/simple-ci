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
