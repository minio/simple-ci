package components

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/gopherjs/vecty"
	"github.com/gopherjs/vecty/elem"
	"github.com/gopherjs/vecty/event"
	"honnef.co/go/js/dom"
)

const (
	INFO = "#00cc74"
	WARN = "#fa9c1d"
	ERR  = "#cd5c5c"
)

var tabIndex = 0

type Line struct {
	Number      int
	Line        string
	numberColor string
	focus       bool
	expanded    bool
	clicked     bool
	vecty.Core
}

func (l *Line) Mount() {
	go func() {
		if !l.focus {
			return
		}

		time.AfterFunc(1*time.Millisecond, func() {
			id := fmt.Sprintf("line-%d", l.Number)
			d := dom.GetWindow().Document()
			h := d.GetElementByID(id).(*dom.HTMLDivElement)
			pos := h.GetBoundingClientRect()
			dom.GetWindow().ScrollBy(int(pos.Left), int(pos.Top))
			vecty.Rerender(l)
		})
	}()

}

func (l *Line) Render() vecty.ComponentOrHTML {
	logColor := "#d8d8d8"
	l.numberColor = "#424242"
	setTabIndex := false
	if strings.Contains(l.Line, "I0614") {
		logColor = INFO
	}
	if strings.Contains(l.Line, "W0614") {
		logColor = WARN
	}
	if strings.Contains(l.Line, "FAIL") {
		setTabIndex = true
		logColor = ERR
	}

	divTabIndex := -1
	if setTabIndex {
		divTabIndex = tabIndex
		tabIndex++
	}
	id := fmt.Sprintf("line-%d", l.Number)
	return elem.Div(
		vecty.Markup(
			vecty.Attribute("id", id),
			vecty.Attribute("tabindex", divTabIndex),
			event.Click(l.Click),
			event.DOMContentLoaded(l.OnLoad),
			event.DoubleClick(l.DoubleClick),
		),
		styler().display("flex").Render(),
		elem.Div(
			styler().color(l.numberColor).floatLeft().marginRight("4px").width("18px").Render(),
			vecty.Text(fmt.Sprintf("%d ", l.Number)),
			vecty.Markup(
				event.MouseOver(l.MouseOver),
				event.MouseOut(l.MouseOut),
				event.Click(l.Click),
			),
		),
		elem.Div(
			styler().color(logColor).floatLeft().marginLeft("30px").whiteSpacePreWrap().Render(),
			vecty.Text(l.Line),
			vecty.Markup(
				event.MouseOver(l.MouseOver),
				event.MouseOut(l.MouseOut),
				event.Click(l.Click),
			),
		),
	)
}

func (l *Line) DoubleClick(*vecty.Event) {
	data := map[string]interface{}{}
	e := json.Unmarshal([]byte(l.Line), &data)
	if e == nil {
		var d []byte
		var e error
		if l.expanded {
			d, e = json.Marshal(data)
		} else {
			d, e = json.MarshalIndent(data, "", " ")
		}
		if e == nil {
			l.Line = string(d)
			vecty.Rerender(l)
			l.expanded = !l.expanded
			return
		} else {
			fmt.Printf("json marshaling err: %v\n", e)
		}
	} else {
		fmt.Printf("json unmarshalling err: %v\n", e)
	}
}

func (l *Line) MouseOver(*vecty.Event) {
	go func() {
		id := fmt.Sprintf("line-%d", l.Number)
		l.numberColor = "#d8d8d8"

		d := dom.GetWindow().Document()
		h := d.GetElementByID(id).GetElementsByTagName("div")[0].(*dom.HTMLDivElement)
		h.Style().SetProperty("color", l.numberColor, "")
		log := d.GetElementByID(id).GetElementsByTagName("div")[1].(*dom.HTMLDivElement)
		log.Style().SetProperty("background-color", "#424242", "")
		vecty.Rerender(l)
	}()
}

func (l *Line) MouseOut(*vecty.Event) {
	go func() {
		if l.clicked {
			return
		}
		id := fmt.Sprintf("line-%d", l.Number)
		l.numberColor = "#424242"

		d := dom.GetWindow().Document()
		h := d.GetElementByID(id).GetElementsByTagName("div")[0].(*dom.HTMLDivElement)
		h.Style().SetProperty("color", l.numberColor, "")
		log := d.GetElementByID(id).GetElementsByTagName("div")[1].(*dom.HTMLDivElement)
		log.Style().SetProperty("background-color", DarkGray, "")
		vecty.Rerender(l)
	}()
}

func (l *Line) Click(e *vecty.Event) {
	go func() {
		locationId := fmt.Sprintf("L%d", l.Number)

		//d := dom.GetWindow().Document()
		//h := d.GetElementByID(id).(*dom.HTMLDivElement)
		dom.GetWindow().Location().Set("hash", "#"+locationId)
		//h.Focus()
		if l.clicked {
			l.MouseOut(e)
		} else {
			l.MouseOver(e)
		}
		l.clicked = !l.clicked
	}()
}

func (l *Line) OnLoad(*vecty.Event) {
	go func() {
		if !l.focus {
			return
		}

		fmt.Printf("focussing %d\n", l.Number)
		id := fmt.Sprintf("line-%d", l.Number)
		d := dom.GetWindow().Document()
		h := d.GetElementByID(id).(*dom.HTMLDivElement)
		h.Focus()
	}()
}

func (l *Line) Key() interface{} {
	return l.Number
}
