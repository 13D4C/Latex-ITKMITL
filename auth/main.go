package main

import (
	"flag"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/filesystem"
	"github.com/gofiber/fiber/v2/middleware/limiter"
	"github.com/gofiber/fiber/v2/middleware/recover"

	"github.com/itkmitl/overleaf-ldap-auth/internal/config"
	"github.com/itkmitl/overleaf-ldap-auth/internal/handlers"
	authldap "github.com/itkmitl/overleaf-ldap-auth/internal/ldap"
	"github.com/itkmitl/overleaf-ldap-auth/internal/overleaf"
	"github.com/itkmitl/overleaf-ldap-auth/internal/proxy"
	"github.com/itkmitl/overleaf-ldap-auth/internal/session"
	"github.com/itkmitl/overleaf-ldap-auth/internal/web"
)

func main() {
	healthcheck := flag.Bool("healthcheck", false, "probe localhost:8080/healthz and exit")
	flag.Parse()
	if *healthcheck {
		runHealthcheck()
	}

	log := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := config.Load()
	if err != nil {
		log.Error("config load failed", "err", err)
		os.Exit(1)
	}

	deps := handlers.Deps{
		LDAP: authldap.New(authldap.Config{
			URL:                cfg.LDAP.URL,
			BindDN:             cfg.LDAP.BindDN,
			BindPassword:       cfg.LDAP.BindPassword,
			BaseDN:             cfg.LDAP.BaseDN,
			UserFilter:         cfg.LDAP.UserFilter,
			EmailAttr:          cfg.LDAP.EmailAttr,
			NameAttr:           cfg.LDAP.NameAttr,
			UseStartTLS:        cfg.LDAP.StartTLS,
			InsecureSkipVerify: cfg.LDAP.SkipTLSVerify,
		}),
		Session: session.NewManager(cfg.Session.Secret, cfg.Session.CookieDomain, cfg.Session.CookieSecure),
		Bridge:  overleaf.New(cfg.Overleaf.InternalURL, cfg.Overleaf.AdminEmail, cfg.Overleaf.AdminPassword, cfg.Session.Secret),
		Log:     log,
	}

	app := fiber.New(fiber.Config{
		DisableStartupMessage: true,
		ProxyHeader:           fiber.HeaderXForwardedFor,
		BodyLimit:             1 << 20, // 1 MB — Overleaf has its own limits past this point
		IdleTimeout:           120 * time.Second,
		ReadTimeout:           60 * time.Second,
		WriteTimeout:          60 * time.Second,
	})
	app.Use(recover.New())
	app.Use(securityHeaders())

	// ---- Public endpoints (no auth required) ----
	app.Get("/healthz", handlers.Health)
	app.Get("/api/csrf", handlers.IssueCSRF(deps))

	// Login API: rate-limited, CSRF-checked. 10 attempts / minute / IP is
	// strict enough to thwart credential stuffing without locking out a
	// legitimate user fat-fingering their password.
	loginLimit := limiter.New(limiter.Config{
		Max:        10,
		Expiration: time.Minute,
		KeyGenerator: func(c *fiber.Ctx) string {
			return c.IP() + "|" + strings.ToLower(c.Get("X-Forwarded-For"))
		},
		LimitReached: func(c *fiber.Ctx) error {
			return c.Status(fiber.StatusTooManyRequests).JSON(fiber.Map{"error": "too many attempts"})
		},
	})
	app.Post("/api/login", loginLimit, handlers.CSRFGuard(deps), handlers.Login(deps))
	app.Post("/api/logout", handlers.CSRFGuard(deps), handlers.Logout(deps))

	// ---- Static SPA (login page) ----
	spaFS, err := web.FS()
	if err != nil {
		log.Error("embed fs", "err", err)
		os.Exit(1)
	}
	indexHTML, err := fs.ReadFile(spaFS, "index.html")
	if err != nil {
		log.Error("read embedded index.html", "err", err)
		os.Exit(1)
	}
	serveLogin := func(c *fiber.Ctx) error {
		c.Set(fiber.HeaderContentType, "text/html; charset=utf-8")
		c.Set("Cache-Control", "no-store")
		return c.Send(indexHTML)
	}
	app.Get("/login", serveLogin)
	// Vite emits hashed assets under /assets/*. Serve them straight from the
	// embedded FS. The middleware strips the matched prefix, so a request to
	// /assets/index-abc.js looks up "assets/index-abc.js" in spaFS.
	app.Use("/assets", filesystem.New(filesystem.Config{
		Root:       http.FS(spaFS),
		PathPrefix: "assets",
		Browse:     false,
	}))
	app.Get("/favicon.ico", func(c *fiber.Ctx) error {
		b, err := fs.ReadFile(spaFS, "favicon.ico")
		if err != nil {
			return c.SendStatus(fiber.StatusNotFound)
		}
		c.Set(fiber.HeaderContentType, "image/x-icon")
		return c.Send(b)
	})

	// ---- Reverse proxy (everything else, gated by session) ----
	rp, err := proxy.New(cfg.Overleaf.InternalURL)
	if err != nil {
		log.Error("proxy init", "err", err)
		os.Exit(1)
	}
	app.Use(handlers.SessionGate(deps), rp)

	log.Info("listening", "addr", cfg.ListenAddr)
	if err := app.Listen(cfg.ListenAddr); err != nil {
		log.Error("fiber exited", "err", err)
		os.Exit(1)
	}
}

// runHealthcheck is the body of the --healthcheck CLI mode. It hits the
// service's own /healthz endpoint and exits with the appropriate code so
// Docker's HEALTHCHECK can use it without bundling curl into the image.
func runHealthcheck() {
	addr := os.Getenv("LISTEN_ADDR")
	if addr == "" {
		addr = ":8080"
	}
	if strings.HasPrefix(addr, ":") {
		addr = "127.0.0.1" + addr
	}
	client := &http.Client{Timeout: 3 * time.Second}
	resp, err := client.Get("http://" + addr + "/healthz")
	if err != nil {
		os.Exit(1)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		os.Exit(1)
	}
	os.Exit(0)
}

// securityHeaders sets a conservative baseline. CSP intentionally permits
// inline styles because Overleaf's own pages rely on them; if you front this
// with a real CSP, scope it to /login only.
func securityHeaders() fiber.Handler {
	return func(c *fiber.Ctx) error {
		c.Set("X-Content-Type-Options", "nosniff")
		c.Set("X-Frame-Options", "SAMEORIGIN")
		c.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		c.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
		return c.Next()
	}
}
