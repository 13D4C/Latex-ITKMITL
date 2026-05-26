// Package config loads runtime configuration from environment variables and
// (optionally) from Docker secret files referenced by *_FILE variants.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

type Config struct {
	ListenAddr string

	LDAP struct {
		URL            string
		BindDN         string
		BindPassword   string
		BaseDN         string
		UserFilter     string
		EmailAttr      string
		NameAttr       string
		StartTLS       bool
		SkipTLSVerify  bool
	}

	Overleaf struct {
		InternalURL   string
		AdminEmail    string
		AdminPassword string
	}

	Session struct {
		Secret       []byte
		CookieDomain string
		CookieSecure bool
	}
}

func Load() (*Config, error) {
	cfg := &Config{}

	cfg.ListenAddr = envOr("LISTEN_ADDR", ":8080")

	cfg.LDAP.URL = mustEnv("LDAP_URL")
	cfg.LDAP.BindDN = composeBindDN(os.Getenv("LDAP_USER"), os.Getenv("LDAP_DN"))
	pw, err := readSecret("LDAP_PASSWORD")
	if err != nil {
		return nil, err
	}
	cfg.LDAP.BindPassword = pw
	cfg.LDAP.BaseDN = mustEnv("LDAP_DN")
	cfg.LDAP.UserFilter = envOr("LDAP_USER_FILTER", "(sAMAccountName=%s)")
	cfg.LDAP.EmailAttr = envOr("LDAP_EMAIL_ATTR", "mail")
	cfg.LDAP.NameAttr = envOr("LDAP_NAME_ATTR", "displayName")
	cfg.LDAP.StartTLS = envBool("LDAP_STARTTLS", true)
	cfg.LDAP.SkipTLSVerify = envBool("LDAP_TLS_SKIP_VERIFY", false)

	cfg.Overleaf.InternalURL = envOr("OVERLEAF_INTERNAL_URL", "http://sharelatex")
	cfg.Overleaf.AdminEmail = os.Getenv("OVERLEAF_ADMIN_EMAIL")
	cfg.Overleaf.AdminPassword, _ = readSecret("OVERLEAF_ADMIN_PASSWORD")

	secret, err := readSecret("SESSION_SECRET")
	if err != nil {
		return nil, err
	}
	if len(secret) < 32 {
		return nil, errors.New("config: SESSION_SECRET must be at least 32 bytes (use: openssl rand -hex 32)")
	}
	cfg.Session.Secret = []byte(secret)
	cfg.Session.CookieDomain = os.Getenv("COOKIE_DOMAIN")
	cfg.Session.CookieSecure = envBool("COOKIE_SECURE", true)

	return cfg, nil
}

// composeBindDN passes LDAP_USER through verbatim. Use whichever form the
// server expects:
//   - full DN:    "CN=ldap_bind,CN=Users,DC=it,DC=kmitl,DC=ac,DC=th"
//   - AD UPN:     "ldap_bind@it.kmitl.ac.th"
//   - AD NetBIOS: "IT\ldap_bind"
//   - AD bare:    "ldap_bind"           (AD only — OpenLDAP requires full DN)
//
// We deliberately don't auto-prefix as CN=<user>,<baseDN> because most
// service accounts live in a sub-OU (CN=Users, OU=ServiceAccounts, etc.),
// not at the base DN itself. Guessing the OU wrong silently breaks bind.
func composeBindDN(user, _ string) string {
	return strings.TrimSpace(user)
}

func mustEnv(k string) string {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		panic(fmt.Sprintf("config: required env %s is empty", k))
	}
	return v
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

func envBool(k string, def bool) bool {
	v := strings.TrimSpace(os.Getenv(k))
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return def
	}
	return b
}

// readSecret prefers the *_FILE variant (Docker secrets) over the inline env.
// Returns empty string with no error if neither is set — let callers decide.
func readSecret(k string) (string, error) {
	if path := os.Getenv(k + "_FILE"); path != "" {
		b, err := os.ReadFile(path)
		if err != nil {
			return "", fmt.Errorf("config: read %s_FILE %q: %w", k, path, err)
		}
		return strings.TrimRight(string(b), "\r\n"), nil
	}
	return os.Getenv(k), nil
}
