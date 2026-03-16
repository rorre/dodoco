package main

import (
	"flag"
	"log"
	"os"
	"path/filepath"
)

func main() {
	home, err := os.UserHomeDir()
	if err != nil {
		log.Fatalf("failed to get home directory: %v", err)
	}
	defaultRulesPath := filepath.Join(home, ".config", "dodoco", "rules.json")
	addr := flag.String("addr", ":8080", "listen address")
	adminAddr := flag.String("admin", ":9090", "admin server listen address")
	rulesPath := flag.String("rules", defaultRulesPath, "path to rules file")
	username := flag.String("username", "", "proxy authentication username")
	password := flag.String("password", "", "proxy authentication password")
	flag.Parse()

	var rules []Rule
	if _, err := os.Stat(*rulesPath); os.IsNotExist(err) {
		log.Printf("warning: rules file %s not found, running as pass-through proxy", *rulesPath)
	} else {
		rules, err = LoadRules(*rulesPath)
		if err != nil {
			log.Fatalf("failed to load rules: %v", err)
		}
	}

	engine, err := NewRuleEngine(rules)
	if err != nil {
		log.Fatalf("failed to compile rules: %v", err)
	}

	if _, err := os.Stat(*rulesPath); !os.IsNotExist(err) {
		if err := WatchRules(engine, *rulesPath); err != nil {
			log.Printf("warning: failed to watch rules file: %v", err)
		}
	}

	if *adminAddr != "" {
		StartAdmin(*adminAddr, *rulesPath, engine)
	}

	p := New(engine)
	if *username != "" {
		p.Username = *username
		p.Password = *password
		log.Printf("proxy authentication enabled")
	}
	log.Printf("dodoco proxy listening on %s", *addr)
	log.Fatal(p.ListenAndServe(*addr))
}
