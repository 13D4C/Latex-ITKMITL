// Package proxy forwards authenticated traffic to the Overleaf container.
// Uses net/http's httputil because Fiber's built-in proxy.Forward does not
// transparently handle WebSocket upgrades (needed by the Overleaf editor).
package proxy

import (
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"

	"github.com/gofiber/adaptor/v2"
	"github.com/gofiber/fiber/v2"
)

// New returns a Fiber handler that reverse-proxies the request to upstream,
// preserving cookies, the Host header, and Upgrade/WebSocket semantics.
func New(upstream string) (fiber.Handler, error) {
	u, err := url.Parse(upstream)
	if err != nil {
		return nil, err
	}
	rp := httputil.NewSingleHostReverseProxy(u)

	originalDirector := rp.Director
	rp.Director = func(r *http.Request) {
		originalDirector(r)
		// Overleaf checks Host for some redirects — give it the upstream's.
		r.Host = u.Host
		// Hide our proxy from upstream logs and let it know the protocol the
		// client used. Trust this only because we control the front edge.
		if proto := r.Header.Get("X-Forwarded-Proto"); proto == "" {
			if r.TLS != nil {
				r.Header.Set("X-Forwarded-Proto", "https")
			} else {
				r.Header.Set("X-Forwarded-Proto", "http")
			}
		}
	}

	rp.ModifyResponse = func(resp *http.Response) error {
		// Overleaf likes to set its session cookie scoped to / — that's fine.
		// Strip any "Secure" flag if we're serving HTTP locally; otherwise
		// the browser will drop the cookie.
		if resp.Request != nil && resp.Request.Header.Get("X-Forwarded-Proto") != "https" {
			cookies := resp.Header["Set-Cookie"]
			for i, ck := range cookies {
				cookies[i] = stripSecure(ck)
			}
			resp.Header["Set-Cookie"] = cookies
		}
		return nil
	}

	return adaptor.HTTPHandler(rp), nil
}

func stripSecure(cookie string) string {
	parts := strings.Split(cookie, ";")
	out := parts[:0]
	for _, p := range parts {
		if strings.EqualFold(strings.TrimSpace(p), "Secure") {
			continue
		}
		out = append(out, p)
	}
	return strings.Join(out, ";")
}
