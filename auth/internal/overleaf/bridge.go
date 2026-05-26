// Package overleaf bridges authenticated LDAP users into Overleaf Community
// Edition, which has no native SSO.
//
// Strategy:
//
//   - Each LDAP user gets a deterministic Overleaf password derived from
//     HKDF(SESSION_SECRET, email). The plaintext password never leaves this
//     process and is recomputed on every login — there's nothing to leak.
//   - On first login: register the user against Overleaf's admin endpoint
//     (an admin must have been created via /launchpad once), then POST to
//     Overleaf's /login to capture the upstream session cookie.
//   - On subsequent logins: POST /login directly.
//   - The captured upstream cookie (overleaf.sid / sharelatex.sid) is set
//     on the client response so the SPA can navigate to / and Overleaf
//     treats them as authenticated.
//
// Rotating SESSION_SECRET invalidates all derived passwords — the next login
// attempt will return 401 from Overleaf, at which point we fall back to the
// admin "set new password" flow and re-bind the user transparently.
package overleaf

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strings"
	"time"

	"golang.org/x/crypto/hkdf"
)

// Overleaf renders the CSRF token in a meta tag on every page. Pattern is
// stable across CE 4.x → 5.x. Cookie name is _csrf.
var reCSRFMeta = regexp.MustCompile(`<meta\s+name=["']ol-csrfToken["']\s+content=["']([^"']+)["']`)

// fetchCSRF GETs /login on the same cookie jar the caller will reuse for the
// subsequent POST, then extracts the token from the ol-csrfToken meta tag.
// We deliberately skip /dev/csrf — it isn't present on every Overleaf build,
// and when missing, the redirect handling makes the response body unreliable.
func (b *Bridge) fetchCSRF(ctx context.Context, client *http.Client) (string, error) {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, b.baseURL+"/login", nil)
	req.Header.Set("Accept", "text/html")
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("csrf: GET /login: %w", err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 256*1024))
	if err != nil {
		return "", fmt.Errorf("csrf: read /login: %w", err)
	}
	m := reCSRFMeta.FindSubmatch(body)
	if m == nil {
		return "", errors.New("csrf: token not found in /login HTML")
	}
	return string(m[1]), nil
}

// SessionCookie returned to the client by Overleaf. Newer builds use
// "overleaf.sid"; older Community Edition still emits "sharelatex.sid".
var KnownCookieNames = []string{"overleaf.sid", "sharelatex.sid"}

type Bridge struct {
	baseURL       string
	adminEmail    string
	adminPassword string
	secret        []byte
	http          *http.Client
}

func New(baseURL, adminEmail, adminPassword string, secret []byte) *Bridge {
	jar, _ := cookiejar.New(nil)
	return &Bridge{
		baseURL:       strings.TrimRight(baseURL, "/"),
		adminEmail:    adminEmail,
		adminPassword: adminPassword,
		secret:        secret,
		http: &http.Client{
			Timeout: 15 * time.Second,
			Jar:     jar,
		},
	}
}

// LoginCookie performs the full bridge: ensure the user exists, log them in,
// return the cookie to forward to the browser. Caller is responsible for
// running this only after LDAP authentication succeeds.
func (b *Bridge) LoginCookie(ctx context.Context, email, displayName string) (*http.Cookie, error) {
	pw := b.derivePassword(email)

	if cookie, err := b.tryLogin(ctx, email, pw); err == nil {
		return cookie, nil
	} else if !errors.Is(err, errInvalidCreds) {
		return nil, err
	}

	// User probably doesn't exist yet (or secret rotated). Provision/reset.
	if err := b.provisionUser(ctx, email, displayName, pw); err != nil {
		return nil, fmt.Errorf("overleaf: provision user: %w", err)
	}
	return b.tryLogin(ctx, email, pw)
}

var errInvalidCreds = errors.New("overleaf: invalid credentials")

func (b *Bridge) tryLogin(ctx context.Context, email, password string) (*http.Cookie, error) {
	// Fresh jar so the admin session (if any) doesn't pollute this call.
	jar, _ := cookiejar.New(nil)
	client := &http.Client{Timeout: b.http.Timeout, Jar: jar, CheckRedirect: noFollow}

	csrf, err := b.fetchCSRF(ctx, client)
	if err != nil {
		return nil, err
	}

	body, _ := json.Marshal(map[string]string{
		"email":    email,
		"password": password,
		"_csrf":    csrf,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/login", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Csrf-Token", csrf)

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("overleaf: login: %w", err)
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	switch resp.StatusCode {
	case 200, 302:
		for _, c := range resp.Cookies() {
			for _, name := range KnownCookieNames {
				if c.Name == name {
					return c, nil
				}
			}
		}
		// Some builds keep the session cookie sticky on the jar (not the
		// response) when the login response is a 200 JSON. Pull it from there.
		if u, err := url.Parse(b.baseURL); err == nil {
			for _, c := range jar.Cookies(u) {
				for _, name := range KnownCookieNames {
					if c.Name == name {
						return c, nil
					}
				}
			}
		}
		return nil, errors.New("overleaf: login OK but no session cookie returned")
	case 401, 403:
		return nil, errInvalidCreds
	default:
		return nil, fmt.Errorf("overleaf: login: unexpected status %d", resp.StatusCode)
	}
}

// provisionUser logs in as admin, asks Overleaf to register the new user, and
// sets their password to `password`. The admin endpoints used here are part
// of Overleaf Community Edition's web/server modules and are stable across
// recent images, but they are NOT a documented public API — pin your Overleaf
// image tag in production and re-validate this path on upgrades.
func (b *Bridge) provisionUser(ctx context.Context, email, name, password string) error {
	if b.adminEmail == "" || b.adminPassword == "" {
		return errors.New("overleaf: OVERLEAF_ADMIN_EMAIL/PASSWORD unset — visit /launchpad to create admin first")
	}

	if err := b.adminLogin(ctx); err != nil {
		return err
	}

	// Step 1: register — returns a setNewPasswordUrl with a one-shot token.
	respBody, status, err := b.authedPost(ctx, "/admin/register", map[string]string{"email": email})
	if err != nil {
		return fmt.Errorf("admin register: %w", err)
	}
	if status != 200 {
		// 409 / "already registered" is fine — we still need to set the password.
		if !bytes.Contains(respBody, []byte("AlreadyRegistered")) && status != 409 {
			return fmt.Errorf("admin register: %d: %s", status, truncate(respBody, 200))
		}
	}

	var reg struct {
		SetNewPasswordURL string `json:"setNewPasswordUrl"`
	}
	_ = json.Unmarshal(respBody, &reg)

	// Step 2: set the password.
	if reg.SetNewPasswordURL == "" {
		// User already existed and admin/register didn't echo a token. Use the
		// admin "send reset" path which returns one we can follow.
		token, err := b.requestPasswordResetToken(ctx, email)
		if err != nil {
			return err
		}
		return b.consumePasswordResetToken(ctx, token, password)
	}

	return b.followSetPasswordURL(ctx, reg.SetNewPasswordURL, password)
}

func (b *Bridge) adminLogin(ctx context.Context) error {
	csrf, err := b.fetchCSRF(ctx, b.http)
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	body, _ := json.Marshal(map[string]string{
		"email":    b.adminEmail,
		"password": b.adminPassword,
		"_csrf":    csrf,
	})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+"/login", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Csrf-Token", csrf)
	resp, err := b.http.Do(req)
	if err != nil {
		return fmt.Errorf("admin login: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	if resp.StatusCode != 200 && resp.StatusCode != 302 {
		return fmt.Errorf("admin login: status %d: %s", resp.StatusCode, truncate(respBody, 200))
	}
	return nil
}

// authedPost sends a JSON POST with the CSRF token attached. Used for all
// admin endpoints after adminLogin populated b.http's cookie jar.
func (b *Bridge) authedPost(ctx context.Context, path string, payload map[string]string) ([]byte, int, error) {
	csrf, err := b.fetchCSRF(ctx, b.http)
	if err != nil {
		return nil, 0, err
	}
	if payload == nil {
		payload = map[string]string{}
	}
	payload["_csrf"] = csrf
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, b.baseURL+path, bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("X-Csrf-Token", csrf)
	resp, err := b.http.Do(req)
	if err != nil {
		return nil, 0, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 8192))
	return respBody, resp.StatusCode, nil
}

func (b *Bridge) requestPasswordResetToken(ctx context.Context, email string) (string, error) {
	raw, status, err := b.authedPost(ctx, "/admin/user/"+url.PathEscape(email)+"/passwordReset", nil)
	if err != nil {
		return "", err
	}
	if status != 200 {
		return "", fmt.Errorf("password reset request: %d: %s", status, truncate(raw, 200))
	}
	var out struct {
		SetNewPasswordURL string `json:"setNewPasswordUrl"`
	}
	if err := json.Unmarshal(raw, &out); err != nil {
		return "", err
	}
	if out.SetNewPasswordURL == "" {
		return "", errors.New("password reset: no token returned")
	}
	return out.SetNewPasswordURL, nil
}

func (b *Bridge) consumePasswordResetToken(ctx context.Context, setURL, password string) error {
	return b.followSetPasswordURL(ctx, setURL, password)
}

func (b *Bridge) followSetPasswordURL(ctx context.Context, setURL, password string) error {
	// CE 5.x returns /user/activate?token=…&user_id=…; older builds returned
	// /user/password/set?passwordResetToken=…. Both flows submit the new
	// password to /user/password/set with the field name passwordResetToken,
	// so we just need to accept either query-param name.
	u, err := url.Parse(setURL)
	if err != nil {
		return err
	}
	token := u.Query().Get("token")
	if token == "" {
		token = u.Query().Get("passwordResetToken")
	}
	if token == "" {
		return errors.New("set-password URL missing token")
	}
	raw, status, err := b.authedPost(ctx, "/user/password/set", map[string]string{
		"passwordResetToken": token,
		"password":           password,
	})
	if err != nil {
		return fmt.Errorf("set password: %w", err)
	}
	if status != 200 {
		return fmt.Errorf("set password: status %d: %s", status, truncate(raw, 200))
	}
	return nil
}

// derivePassword turns the user's email into a 32-byte URL-safe password,
// stable as long as SESSION_SECRET stays the same.
func (b *Bridge) derivePassword(email string) string {
	r := hkdf.New(sha256New, b.secret, []byte("overleaf-bridge-v1"), []byte(strings.ToLower(email)))
	buf := make([]byte, 24)
	_, _ = io.ReadFull(r, buf)
	// base64 → 32 chars, all ASCII, safe for Overleaf's password rules.
	return encodeURL(buf)
}

func truncate(b []byte, n int) string {
	if len(b) <= n {
		return string(b)
	}
	return string(b[:n]) + "…"
}

func noFollow(req *http.Request, via []*http.Request) error {
	return http.ErrUseLastResponse
}
