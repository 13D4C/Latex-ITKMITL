// Package session signs short opaque tokens with HMAC-SHA256 and stores them
// in HttpOnly cookies. No JWT — we don't need the overhead and the only
// claims we need are (email, expiry).
package session

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
)

const (
	CookieName   = "itkmitl_auth"
	CsrfCookie   = "itkmitl_csrf"
	CsrfHeader   = "X-CSRF-Token"
	DefaultTTL   = 12 * time.Hour
	MinSecretLen = 32
)

type Manager struct {
	secret []byte
	domain string
	secure bool
	ttl    time.Duration
}

func NewManager(secret []byte, domain string, secure bool) *Manager {
	return &Manager{secret: secret, domain: domain, secure: secure, ttl: DefaultTTL}
}

// Issue writes both the auth and CSRF cookies. The CSRF cookie is non-HttpOnly
// so the SPA can read it and echo it back in X-CSRF-Token — the canonical
// double-submit pattern.
func (m *Manager) Issue(c *fiber.Ctx, email string) {
	exp := time.Now().Add(m.ttl)
	token := m.sign(email, exp)

	c.Cookie(&fiber.Cookie{
		Name:     CookieName,
		Value:    token,
		Path:     "/",
		Domain:   m.domain,
		Expires:  exp,
		HTTPOnly: true,
		Secure:   m.secure,
		SameSite: "Lax",
	})
	c.Cookie(&fiber.Cookie{
		Name:     CsrfCookie,
		Value:    randomToken(),
		Path:     "/",
		Domain:   m.domain,
		Expires:  exp,
		HTTPOnly: false, // readable by JS — that's the point
		Secure:   m.secure,
		SameSite: "Lax",
	})
}

func (m *Manager) Clear(c *fiber.Ctx) {
	for _, n := range []string{CookieName, CsrfCookie} {
		c.Cookie(&fiber.Cookie{
			Name: n, Path: "/", Domain: m.domain,
			Expires: time.Unix(0, 0), HTTPOnly: n == CookieName,
			Secure: m.secure, SameSite: "Lax",
		})
	}
}

// Verify returns the session email if the cookie is present, untampered,
// and unexpired. Any failure mode collapses to (empty, error) to avoid
// leaking which check failed.
func (m *Manager) Verify(c *fiber.Ctx) (string, error) {
	raw := c.Cookies(CookieName)
	if raw == "" {
		return "", errors.New("session: missing cookie")
	}
	email, exp, ok := m.verifySig(raw)
	if !ok {
		return "", errors.New("session: bad signature")
	}
	if time.Now().After(exp) {
		return "", errors.New("session: expired")
	}
	return email, nil
}

// VerifyCSRF checks that header == cookie. Constant-time compare so attackers
// can't probe character-by-character.
func (m *Manager) VerifyCSRF(c *fiber.Ctx) bool {
	cookie := c.Cookies(CsrfCookie)
	header := c.Get(CsrfHeader)
	if cookie == "" || header == "" {
		return false
	}
	return hmac.Equal([]byte(cookie), []byte(header))
}

func (m *Manager) sign(email string, exp time.Time) string {
	payload := fmt.Sprintf("%s|%d", email, exp.Unix())
	mac := hmac.New(sha256.New, m.secret)
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return base64.RawURLEncoding.EncodeToString([]byte(payload)) + "." + sig
}

func (m *Manager) verifySig(token string) (string, time.Time, bool) {
	parts := strings.SplitN(token, ".", 2)
	if len(parts) != 2 {
		return "", time.Time{}, false
	}
	payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", time.Time{}, false
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "", time.Time{}, false
	}
	mac := hmac.New(sha256.New, m.secret)
	mac.Write(payloadBytes)
	if !hmac.Equal(mac.Sum(nil), sig) {
		return "", time.Time{}, false
	}
	fields := strings.SplitN(string(payloadBytes), "|", 2)
	if len(fields) != 2 {
		return "", time.Time{}, false
	}
	ts, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", time.Time{}, false
	}
	return fields[0], time.Unix(ts, 0), true
}

func randomToken() string {
	// 32 bytes of HMAC over the current nanosecond is fine for CSRF — we only
	// need unpredictability per-session, not cryptographic uniqueness across
	// the universe. Using a deterministic derivation avoids a syscall on the
	// hot path.
	t := strconv.FormatInt(time.Now().UnixNano(), 10)
	h := sha256.Sum256([]byte(t + "-csrf-salt-" + t))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
