package components

import (
	"github.com/gopherjs/vecty"
)

const (
	DarkGray      = "#141729"
	DarkGreen     = "#228a00"
	CourierNew    = "\"Courier New\", Courier, monospace"
	SourceSansPro = "\"Source Sans Pro\", sans-serif"
	SourceCodePro = "source-code-pro, Monaco, \"Bitstream Vera Sans Mono\", \"Lucida Console\", Terminal, monospace"
	OpenSans      = "\"Open Sans\", sans-serif"
)

type style struct {
	styles map[string]string
}

func (s *style) isMarkupOrChild() {}

func (s *style) Markup() vecty.MarkupList {
	markups := []vecty.Applyer{}
	for k, v := range s.styles {
		markups = append(markups, vecty.Style(k, v))
	}
	return vecty.Markup(markups...)
}

func (s *style) Render() vecty.MarkupList {
	return s.Markup()
}

func (s *style) con(k, v string) *style {
	if s.styles == nil {
		s.styles = make(map[string]string)
	}
	s.styles[k] = v
	return s
}

func styler() *style {
	return new(style)
}

func (s *style) whiteSpacePreWrap() *style {
	return s.whiteSpace("pre-wrap")
}

func (s *style) whiteSpacePre() *style {
	return s.whiteSpace("pre")
}

func (s *style) whiteSpacePreLine() *style {
	return s.whiteSpace("pre-line")
}

func (s *style) whiteSpace(val string) *style {
	return s.con("white-space", val)
}

func (s *style) clear(val string) *style {
	return s.con("clear", val)
}

func (s *style) overflow(val string) *style {
	return s.con("overflow", val)
}

func (s *style) boxSizing(val string) *style {
	return s.con("box-sizing", val)
}

func (s *style) marginLeft(margin string) *style {
	return s.con("margin-left", margin)
}

func (s *style) marginRight(margin string) *style {
	return s.con("margin-right", margin)
}

func (s *style) marginBottom(margin string) *style {
	return s.con("margin-bottom", margin)
}

func (s *style) floatLeft() *style {
	return s.float("left")
}

func (s *style) float(orientation string) *style {
	return s.con("float", orientation)
}

func (s *style) bold() *style {
	return s.fontWeight("bold")
}

func (s *style) padding(pad string) *style {
	return s.con("padding", pad)
}

func (s *style) fontWeight(weight string) *style {
	return s.con("font-weight", weight)
}

func (s *style) fontSize(size string) *style {
	return s.con("font-size", size)
}

func (s *style) color(color string) *style {
	return s.con("color", color)
}

func (s *style) lineHeight(height string) *style {
	return s.con("line-height", height)
}

func (s *style) bgcolor(color string) *style {
	return s.con("background-color", color)
}

func (s *style) display(val string) *style {
	return s.con("display", val)
}

func (s *style) flexDirection(val string) *style {
	return s.con("flex-direction", val)
}

func (s *style) fontFamily(font string) *style {
	return s.con("font-family", font)
}

func (s *style) position(pos string) *style {
	return s.con("position", pos)
}

func (s *style) left(left string) *style {
	return s.con("left", left)
}

func (s *style) bottom(bottom string) *style {
	return s.con("bottom", bottom)
}

func (s *style) width(width string) *style {
	return s.con("width", width)
}
