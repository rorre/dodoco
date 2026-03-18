package proxy

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
)

//go:embed static/admin.html
var adminHTML []byte

type interfaceInfo struct {
	Name      string   `json:"name"`
	Addresses []string `json:"addresses"`
}

func StartAdmin(listenAddr string, rulesPath string, engine *RuleEngine) {
	mux := http.NewServeMux()

	mux.HandleFunc("/api/rules", func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case http.MethodGet:
			handleGetRules(w, rulesPath)
		case http.MethodPut:
			handlePutRules(w, r, rulesPath, engine)
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		}
	})

	mux.HandleFunc("/api/interfaces", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		handleGetInterfaces(w)
	})

	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(adminHTML)
	})

	go func() {
		log.Printf("admin server listening on %s", listenAddr)
		if err := http.ListenAndServe(listenAddr, mux); err != nil {
			log.Printf("admin server error: %v", err)
		}
	}()
}

func handleGetRules(w http.ResponseWriter, rulesPath string) {
	data, err := os.ReadFile(rulesPath)
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to read rules: %v", err), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	w.Write(data)
}

func handlePutRules(w http.ResponseWriter, r *http.Request, rulesPath string, engine *RuleEngine) {
	var f ruleFile
	if err := json.NewDecoder(r.Body).Decode(&f); err != nil {
		http.Error(w, fmt.Sprintf("invalid JSON: %v", err), http.StatusBadRequest)
		return
	}

	for host, target := range f.Rules {
		rule := Rule{
			HostRule:        host,
			TargetInterface: target.TargetInterface,
			TargetDNS:       target.TargetDNS,
		}
		if err := rule.Validate(); err != nil {
			http.Error(w, fmt.Sprintf("invalid rule %q: %v", host, err), http.StatusBadRequest)
			return
		}
	}

	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to marshal rules: %v", err), http.StatusInternalServerError)
		return
	}

	if err := os.WriteFile(rulesPath, data, 0644); err != nil {
		http.Error(w, fmt.Sprintf("failed to write rules: %v", err), http.StatusInternalServerError)
		return
	}

	if err := engine.Reload(rulesPath); err != nil {
		http.Error(w, fmt.Sprintf("rules saved but reload failed: %v", err), http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func handleGetInterfaces(w http.ResponseWriter) {
	ifaces, err := net.Interfaces()
	if err != nil {
		http.Error(w, fmt.Sprintf("failed to list interfaces: %v", err), http.StatusInternalServerError)
		return
	}

	result := make([]interfaceInfo, 0, len(ifaces))
	for _, iface := range ifaces {
		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}
		addrStrs := make([]string, 0, len(addrs))
		for _, a := range addrs {
			addrStrs = append(addrStrs, a.String())
		}
		result = append(result, interfaceInfo{
			Name:      iface.Name,
			Addresses: addrStrs,
		})
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(result)
}
