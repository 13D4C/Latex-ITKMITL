// Package handlers wires the HTTP routes for the auth service.
package handlers

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"

	authldap "github.com/itkmitl/overleaf-ldap-auth/internal/ldap"
	"github.com/itkmitl/overleaf-ldap-auth/internal/overleaf"
	"github.com/itkmitl/overleaf-ldap-auth/internal/session"
)

type Deps struct {
	LDAP    *authldap.Client
	Session *session.Manager
	Bridge  *overleaf.Bridge
	Log     *slog.Logger
}

type loginReq struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// Login validates LDAP creds, provisions/logs the user in Overleaf, and sets
// both our own session cookie and the upstream Overleaf cookie on the response.
func Login(d Deps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var req loginReq
		if err := c.BodyParser(&req); err != nil {
			return generic(c, fiber.StatusBadRequest)
		}
		req.Username = strings.TrimSpace(req.Username)
		if req.Username == "" || req.Password == "" {
			return generic(c, fiber.StatusBadRequest)
		}

		info, err := d.LDAP.Authenticate(req.Username, req.Password)
		if err != nil {
			d.Log.Info("ldap auth failed", "user", req.Username, "err", err)
			// Constant delay frustrates timing-based user enumeration.
			time.Sleep(250 * time.Millisecond)
			return generic(c, fiber.StatusUnauthorized)
		}

		ctx, cancel := context.WithTimeout(c.Context(), 20*time.Second)
		defer cancel()

		upstream, err := d.Bridge.LoginCookie(ctx, info.Email, info.Name)
		if err != nil {
			d.Log.Error("overleaf bridge failed", "email", info.Email, "err", err)
			return generic(c, fiber.StatusBadGateway)
		}

		c.Cookie(&fiber.Cookie{
			Name:     upstream.Name,
			Value:    upstream.Value,
			Path:     "/",
			Expires:  upstream.Expires,
			MaxAge:   upstream.MaxAge,
			HTTPOnly: true,
			Secure:   cookieSecure(c),
			SameSite: "Lax",
		})

		d.Session.Issue(c, info.Email)
		d.Log.Info("login ok", "email", info.Email)
		return c.JSON(fiber.Map{"ok": true, "redirect": "/project"})
	}
}

func Logout(d Deps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		d.Session.Clear(c)
		for _, name := range overleaf.KnownCookieNames {
			c.Cookie(&fiber.Cookie{
				Name: name, Path: "/",
				Expires:  time.Unix(0, 0),
				HTTPOnly: true,
				Secure:   cookieSecure(c),
				SameSite: "Lax",
			})
		}
		return c.JSON(fiber.Map{"ok": true})
	}
}

// CSRFGuard rejects mutating requests without a matching double-submit token.
func CSRFGuard(d Deps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		switch c.Method() {
		case fiber.MethodPost, fiber.MethodPut, fiber.MethodPatch, fiber.MethodDelete:
			if !d.Session.VerifyCSRF(c) {
				return generic(c, fiber.StatusForbidden)
			}
		}
		return c.Next()
	}
}

// SessionGate forwards requests upstream only if our HMAC cookie checks out.
// Unauthenticated browser navigations get redirected to /login; XHRs get 401.
func SessionGate(d Deps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if _, err := d.Session.Verify(c); err != nil {
			if wantsHTML(c) {
				return c.Redirect("/login", http.StatusFound)
			}
			return generic(c, fiber.StatusUnauthorized)
		}
		return c.Next()
	}
}

// IssueCSRF gives the SPA a token before the first POST. Issued to anonymous
// callers — the token alone doesn't grant access; it must pair with the
// auth cookie that Login() issues.
func IssueCSRF(d Deps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		token := c.Cookies(session.CsrfCookie)
		if token == "" {
			token = randomToken()
			c.Cookie(&fiber.Cookie{
				Name:     session.CsrfCookie,
				Value:    token,
				Path:     "/",
				Expires:  time.Now().Add(2 * time.Hour),
				HTTPOnly: false,
				Secure:   cookieSecure(c),
				SameSite: "Lax",
			})
		}
		return c.JSON(fiber.Map{"csrf": token})
	}
}

func Health(c *fiber.Ctx) error {
	return c.JSON(fiber.Map{"status": "ok"})
}

func generic(c *fiber.Ctx, status int) error {
	return c.Status(status).JSON(fiber.Map{"error": http.StatusText(status)})
}

func wantsHTML(c *fiber.Ctx) bool {
	accept := c.Get("Accept")
	if accept == "" {
		return true
	}
	a := strings.ToLower(accept)
	return strings.Contains(a, "text/html") || strings.Contains(a, "application/xhtml")
}

func cookieSecure(c *fiber.Ctx) bool {
	return c.Protocol() == "https" || c.Get("X-Forwarded-Proto") == "https"
}

func randomToken() string {
	b := make([]byte, 24)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
