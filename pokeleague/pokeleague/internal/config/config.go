// Package config loads settings from environment variables (12-factor).
// On AWS these come from the ECS task definition, with secrets injected from
// AWS Secrets Manager / SSM Parameter Store rather than baked into images.
package config

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"time"
)

type Config struct {
	Env      string // "development" or "production"
	HTTPAddr string
	LogLevel slog.Level

	DatabaseURL string
	DBMaxConns  int32
	AutoMigrate bool
	LockTimeout time.Duration

	JWTPrivateKey   ed25519.PrivateKey
	JWTKeyEphemeral bool // true if generated at start-up (development only)
	JWTIssuer       string
	JWTAudience     string
	AccessTokenTTL  time.Duration
	RefreshTokenTTL time.Duration
	SessionTTL      time.Duration

	RequestTimeout    time.Duration
	ShutdownTimeout   time.Duration
	AuthRatePerMinute int
	TrustProxy        bool
	HashConcurrency   int

	BootstrapAdminUsername string
	BootstrapAdminEmail    string
	BootstrapAdminPassword string
}

func (c Config) IsProduction() bool { return c.Env == "production" }

// Load reads and validates configuration. It collects every problem before
// failing, so a misconfigured deploy reports all issues at once.
func Load() (Config, error) {
	var errs []error
	c := Config{
		Env:      env("APP_ENV", "development"),
		HTTPAddr: env("HTTP_ADDR", ":8080"),

		DatabaseURL: os.Getenv("DATABASE_URL"),
		DBMaxConns:  int32(envInt("DB_MAX_CONNS", 10, &errs)),
		AutoMigrate: envBool("AUTO_MIGRATE", true, &errs),
		LockTimeout: envDur("DB_LOCK_TIMEOUT", 3*time.Second, &errs),

		JWTIssuer:       env("JWT_ISSUER", "pokeleague-api"),
		JWTAudience:     env("JWT_AUDIENCE", "pokeleague-clients"),
		AccessTokenTTL:  envDur("ACCESS_TOKEN_TTL", 15*time.Minute, &errs),
		RefreshTokenTTL: envDur("REFRESH_TOKEN_TTL", 7*24*time.Hour, &errs),
		SessionTTL:      envDur("SESSION_TTL", 30*24*time.Hour, &errs),

		RequestTimeout:    envDur("REQUEST_TIMEOUT", 10*time.Second, &errs),
		ShutdownTimeout:   envDur("SHUTDOWN_TIMEOUT", 20*time.Second, &errs),
		AuthRatePerMinute: envInt("AUTH_RATE_PER_MINUTE", 20, &errs),
		TrustProxy:        envBool("TRUST_PROXY", false, &errs),
		HashConcurrency:   envInt("PASSWORD_HASH_CONCURRENCY", 8, &errs),

		BootstrapAdminUsername: os.Getenv("BOOTSTRAP_ADMIN_USERNAME"),
		BootstrapAdminEmail:    os.Getenv("BOOTSTRAP_ADMIN_EMAIL"),
		BootstrapAdminPassword: os.Getenv("BOOTSTRAP_ADMIN_PASSWORD"),
	}

	if err := c.LogLevel.UnmarshalText([]byte(env("LOG_LEVEL", "info"))); err != nil {
		errs = append(errs, fmt.Errorf("LOG_LEVEL: %w", err))
	}
	if c.Env != "development" && c.Env != "production" {
		errs = append(errs, errors.New(`APP_ENV must be "development" or "production"`))
	}
	if c.DatabaseURL == "" {
		errs = append(errs, errors.New("DATABASE_URL is required"))
	}
	if c.AccessTokenTTL <= 0 || c.AccessTokenTTL > time.Hour {
		errs = append(errs, errors.New("ACCESS_TOKEN_TTL must be in (0, 1h]: access tokens cannot be revoked, so keep them short"))
	}
	if c.RefreshTokenTTL <= 0 || c.SessionTTL < c.RefreshTokenTTL {
		errs = append(errs, errors.New("REFRESH_TOKEN_TTL must be positive and no longer than SESSION_TTL"))
	}

	switch seed := os.Getenv("JWT_ED25519_SEED"); {
	case seed != "":
		b, err := base64.StdEncoding.DecodeString(seed)
		if err != nil || len(b) != ed25519.SeedSize {
			errs = append(errs, errors.New("JWT_ED25519_SEED must be 32 bytes, base64-encoded (openssl rand -base64 32)"))
		} else {
			c.JWTPrivateKey = ed25519.NewKeyFromSeed(b)
		}
	case c.IsProduction():
		errs = append(errs, errors.New("JWT_ED25519_SEED is required in production"))
	default:
		// Development convenience: tokens stop working on restart.
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			errs = append(errs, err)
		}
		c.JWTPrivateKey, c.JWTKeyEphemeral = priv, true
	}

	if c.BootstrapAdminUsername != "" && (c.BootstrapAdminEmail == "" || c.BootstrapAdminPassword == "") {
		errs = append(errs, errors.New("BOOTSTRAP_ADMIN_EMAIL and BOOTSTRAP_ADMIN_PASSWORD are required with BOOTSTRAP_ADMIN_USERNAME"))
	}

	return c, errors.Join(errs...)
}

func env(key, def string) string {
	if v, ok := os.LookupEnv(key); ok && v != "" {
		return v
	}
	return def
}

func envInt(key string, def int, errs *[]error) int {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	n, err := strconv.Atoi(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", key, err))
	}
	return n
}

func envBool(key string, def bool, errs *[]error) bool {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", key, err))
	}
	return b
}

func envDur(key string, def time.Duration, errs *[]error) time.Duration {
	v := os.Getenv(key)
	if v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		*errs = append(*errs, fmt.Errorf("%s: %w", key, err))
	}
	return d
}
