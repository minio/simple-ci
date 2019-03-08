package ci

import (
	"io/ioutil"
	"net/http"
	"net/url"

	"github.com/golang/glog"
)

var gitCookiePath = "gitcookie/.gitcookie"
var gitCookieURL = "googlesource.com"

type gitCookieJar struct {
	cookie []*http.Cookie
}

func (g *gitCookieJar) SetCookies(u *url.URL, cookies []*http.Cookie) {}

func (g *gitCookieJar) Cookies(u *url.URL) []*http.Cookie {
	if u == nil {
		return nil
	}

	if u.Host == gitCookieURL {
		if g.cookie != nil {
			return g.cookie
		}
		cookieData, err := ioutil.ReadFile(gitCookiePath)
		if err != nil {
			glog.Errorf("error getting cookie: %v", err)
			return nil
		}
		c := http.Cookie{
			Name:  "o",
			Value: string(cookieData),
		}
		g.cookie = []*http.Cookie{&c}
		return g.cookie
	}
	return nil

}
