// Package ldap is a thin wrapper around go-ldap/v3 used by the auth service
// to authenticate users against an LDAP / Active Directory server.
//
// Flow (standard "search-then-bind"):
//  1. Open a TCP/TLS connection to the LDAP URL.
//  2. Bind as a service account (BindDN / BindPassword).
//  3. Search BaseDN with UserFilter to locate the user's DN.
//  4. Re-bind as that DN using the password supplied by the user.
//
// The search-then-bind pattern is preferred over straight DN-binding because
// it lets users authenticate with whatever attribute the filter targets
// (sAMAccountName, mail, uid) rather than the raw distinguished name.
package ldap

import (
	"crypto/tls"
	"errors"
	"fmt"
	"strings"

	goldap "github.com/go-ldap/ldap/v3"
)

var (
	ErrInvalidCredentials = errors.New("invalid ldap credentials")
	ErrUserNotFound       = errors.New("ldap user not found")
)

type Config struct {
	URL                string
	BindDN             string
	BindPassword       string
	BaseDN             string
	UserFilter         string
	EmailAttr          string
	NameAttr           string
	UseStartTLS        bool
	InsecureSkipVerify bool
}

type UserInfo struct {
	DN       string
	Email    string
	Name     string
	Username string
}

type Client struct {
	cfg Config
}

func New(cfg Config) *Client {
	if cfg.UserFilter == "" {
		cfg.UserFilter = "(sAMAccountName=%s)"
	}
	if cfg.EmailAttr == "" {
		cfg.EmailAttr = "mail"
	}
	if cfg.NameAttr == "" {
		cfg.NameAttr = "displayName"
	}
	return &Client{cfg: cfg}
}

// Authenticate verifies username+password against LDAP. The username is
// escaped before being substituted into the filter to prevent injection
// (e.g. a user typing `*)(uid=*` could otherwise broaden the search).
func (c *Client) Authenticate(username, password string) (*UserInfo, error) {
	if username == "" || password == "" {
		return nil, ErrInvalidCredentials
	}

	conn, err := c.dial()
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	if c.cfg.BindDN != "" {
		if err := conn.Bind(c.cfg.BindDN, c.cfg.BindPassword); err != nil {
			return nil, fmt.Errorf("ldap: service bind failed: %w", err)
		}
	}

	entry, err := c.searchUser(conn, username)
	if err != nil {
		return nil, err
	}

	if err := conn.Bind(entry.DN, password); err != nil {
		return nil, ErrInvalidCredentials
	}

	email := strings.ToLower(strings.TrimSpace(entry.GetAttributeValue(c.cfg.EmailAttr)))
	if email == "" {
		// Fall back to <username>@<derived-domain>. Some directories don't
		// populate `mail`, but Overleaf requires an email for every account.
		email = strings.ToLower(username) + "@" + domainFromDN(c.cfg.BaseDN)
	}

	return &UserInfo{
		DN:       entry.DN,
		Email:    email,
		Name:     strings.TrimSpace(entry.GetAttributeValue(c.cfg.NameAttr)),
		Username: username,
	}, nil
}

func (c *Client) dial() (*goldap.Conn, error) {
	tlsCfg := &tls.Config{InsecureSkipVerify: c.cfg.InsecureSkipVerify} //nolint:gosec
	conn, err := goldap.DialURL(c.cfg.URL, goldap.DialWithTLSConfig(tlsCfg))
	if err != nil {
		return nil, fmt.Errorf("ldap: dial %q: %w", c.cfg.URL, err)
	}
	if c.cfg.UseStartTLS && strings.HasPrefix(c.cfg.URL, "ldap://") {
		if err := conn.StartTLS(tlsCfg); err != nil {
			conn.Close()
			return nil, fmt.Errorf("ldap: starttls: %w", err)
		}
	}
	return conn, nil
}

func (c *Client) searchUser(conn *goldap.Conn, username string) (*goldap.Entry, error) {
	filter := strings.ReplaceAll(c.cfg.UserFilter, "%s", goldap.EscapeFilter(username))
	req := goldap.NewSearchRequest(
		c.cfg.BaseDN,
		goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		2, 10, false,
		filter,
		[]string{c.cfg.EmailAttr, c.cfg.NameAttr},
		nil,
	)
	res, err := conn.Search(req)
	if err != nil {
		return nil, fmt.Errorf("ldap: search: %w", err)
	}
	switch len(res.Entries) {
	case 0:
		return nil, ErrUserNotFound
	case 1:
		return res.Entries[0], nil
	default:
		return nil, fmt.Errorf("ldap: filter %q matched %d entries — must be unique", filter, len(res.Entries))
	}
}

// domainFromDN turns "DC=it,DC=kmitl,DC=ac,DC=th" into "it.kmitl.ac.th".
func domainFromDN(baseDN string) string {
	parts := strings.Split(baseDN, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		kv := strings.SplitN(strings.TrimSpace(p), "=", 2)
		if len(kv) == 2 && strings.EqualFold(kv[0], "dc") {
			out = append(out, kv[1])
		}
	}
	return strings.Join(out, ".")
}
