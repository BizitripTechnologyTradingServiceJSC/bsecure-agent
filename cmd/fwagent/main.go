package main

import (
	"log"
	"os"
	"strings"
	"time"

	agent "github.com/BizitripTechnologyTradingServiceJSC/bsecure-agent/internal"
)

func env(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// envOpt returns the variable's value when it is set, even to the empty string (an empty log path disables that source).
func envOpt(k, d string) string {
	if v, ok := os.LookupEnv(k); ok {
		return v
	}
	return d
}

func main() {
	host, _ := os.Hostname()
	cfg := agent.Config{
		PanelURL:    strings.TrimRight(env("PANEL_URL", ""), "/"),
		Name:        env("AGENT_NAME", host),
		EnrollToken: env("ENROLL_TOKEN", ""),
		StateDir:    env("STATE_DIR", "/var/lib/fwagent"),
		AuthLog:     envOpt("AUTH_LOG", env("LOG_FILE", "/var/log/auth.log")),
		NginxLog:    envOpt("NGINX_ACCESS_LOG", "/var/log/nginx/access.log"),
		Syslog:      envOpt("SYSLOG", "/var/log/syslog"),
		DryRun:      env("DRY_RUN", "true") != "false", // safe by default
		Allowlist:   strings.Split(env("ADMIN_ALLOWLIST", ""), ","),
		AllowConfig: env("ALLOW_CONFIG_CHANGES", "false") == "true",
		PanelPubKey: env("PANEL_PUBKEY", ""),
	}
	if cfg.PanelURL == "" {
		log.Fatal("PANEL_URL is required")
	}
	cfg.TLS = agent.TLSConfig{CAFile: env("PANEL_CA_FILE", ""), CertFile: env("AGENT_CERT_FILE", ""), KeyFile: env("AGENT_KEY_FILE", "")}
	cfg.AllowInsecure = env("ALLOW_INSECURE_HTTP", "false") == "true"
	if cfg.AllowInsecure && !strings.HasPrefix(cfg.PanelURL, "https://") {
		log.Printf("WARNING: PANEL_URL is not https; agent token and commands travel in clear text")
	}
	fw := &agent.NFT{DryRun: cfg.DryRun, Run: agent.ExecRunner}
	a, err := agent.New(cfg, fw)
	if err != nil {
		log.Fatal(err)
	}
	if err := a.EnrollWithRetry(time.Sleep); err != nil {
		log.Fatalf("enroll: %v", err)
	}
	log.Printf("fwagent %s started name=%s dryRun=%v", agent.Version, cfg.Name, cfg.DryRun)
	log.Fatal(a.Run())
}
