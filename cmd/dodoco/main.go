package main

import (
	"encoding/json"
	"flag"
	"log"
	"os"
	"path/filepath"
	"strings"

	"github.com/rorre/dodoco/proxy"
)

type Config struct {
	Addr      string `json:"addr"`
	Admin     string `json:"admin"`
	RulesPath string `json:"rulesPath"`
	Username  string `json:"username"`
	Password  string `json:"password"`
	CACert    string `json:"caCert"`
	CAKey     string `json:"caKey"`
}

func loadConfigFile(path string) (Config, error) {
	var cfg Config
	data, err := os.ReadFile(path)
	if err != nil {
		return cfg, err
	}
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home directory: %v", err)
	}
	configDir := filepath.Join(home, ".config", "dodoco")
	defaultRulesPath := filepath.Join(configDir, "rules.json")
	defaultConfigPath := filepath.Join(configDir, "config.json")
	defaultCACert := filepath.Join(configDir, "ca.crt")
	defaultCAKey := filepath.Join(configDir, "ca.key")

	configPath := flag.String("config", defaultConfigPath, "path to config file")
	addr := flag.String("addr", "", "listen address")
	adminAddr := flag.String("admin", "", "admin server listen address")
	rulesPath := flag.String("rulesPath", "", "path to rules file")
	username := flag.String("username", "", "proxy authentication username")
	password := flag.String("password", "", "proxy authentication password")
	caCert := flag.String("caCert", "", "path to CA certificate")
	caKey := flag.String("caKey", "", "path to CA private key")
	flag.Parse()

	// Load config file defaults
	cfg := Config{
		Addr:      ":8080",
		Admin:     ":9090",
		RulesPath: defaultRulesPath,
		CACert:    defaultCACert,
		CAKey:     defaultCAKey,
	}
	if fileCfg, err := loadConfigFile(*configPath); err == nil {
		log.Printf("loaded config from %s", *configPath)
		if fileCfg.Addr != "" {
			cfg.Addr = fileCfg.Addr
		}
		if fileCfg.Admin != "" {
			cfg.Admin = fileCfg.Admin
		}
		if fileCfg.RulesPath != "" {
			cfg.RulesPath = fileCfg.RulesPath
		}
		if fileCfg.Username != "" {
			cfg.Username = fileCfg.Username
		}
		if fileCfg.Password != "" {
			cfg.Password = fileCfg.Password
		}
		if fileCfg.CACert != "" {
			cfg.CACert = fileCfg.CACert
		}
		if fileCfg.CAKey != "" {
			cfg.CAKey = fileCfg.CAKey
		}
	}

	// Command-line flags override config file
	flag.Visit(func(f *flag.Flag) {
		switch f.Name {
		case "addr":
			cfg.Addr = *addr
		case "admin":
			cfg.Admin = *adminAddr
		case "rulesPath":
			cfg.RulesPath = *rulesPath
		case "username":
			cfg.Username = *username
		case "password":
			cfg.Password = *password
		case "caCert":
			cfg.CACert = *caCert
		case "caKey":
			cfg.CAKey = *caKey
		}
	})

	if strings.HasPrefix(cfg.RulesPath, "~/") {
		cfg.RulesPath = filepath.Join(home, cfg.RulesPath[2:])
	}
	if strings.HasPrefix(cfg.CACert, "~/") {
		cfg.CACert = filepath.Join(home, cfg.CACert[2:])
	}
	if strings.HasPrefix(cfg.CAKey, "~/") {
		cfg.CAKey = filepath.Join(home, cfg.CAKey[2:])
	}

	var rules []proxy.Rule
	if _, err := os.Stat(cfg.RulesPath); os.IsNotExist(err) {
		log.Printf("warning: rules file %s not found, running as pass-through proxy", cfg.RulesPath)
	} else {
		rules, err = proxy.LoadRules(cfg.RulesPath)
		if err != nil {
			log.Fatalf("failed to load rules: %v", err)
		}
	}

	engine, err := proxy.NewRuleEngine(rules)
	if err != nil {
		log.Fatalf("failed to compile rules: %v", err)
	}

	if _, err := os.Stat(cfg.RulesPath); !os.IsNotExist(err) {
		if err := proxy.WatchRules(engine, cfg.RulesPath); err != nil {
			log.Printf("warning: failed to watch rules file: %v", err)
		}
	}

	if cfg.Admin != "" {
		proxy.StartAdmin(cfg.Admin, cfg.RulesPath, engine)
	}

	p := proxy.New(engine)
	if cfg.Username != "" {
		p.Username = cfg.Username
		p.Password = cfg.Password
		log.Printf("proxy authentication enabled")
	}

	// Initialize MITM
	if cfg.CACert != "" && cfg.CAKey != "" {
		if err := p.InitMITM(cfg.CACert, cfg.CAKey); err != nil {
			log.Printf("MITM initialization failed: %v (HTTPS modification disabled)", err)
		} else {
			log.Printf("MITM initialized with CA: %s", cfg.CACert)
			if !p.CheckCAInstalled() {
				log.Printf("warning: CA certificate is not installed in system trust store")
			}
		}
	}

	log.Printf("dodoco proxy listening on %s", cfg.Addr)
	log.Fatal(p.ListenAndServe(cfg.Addr))
}

