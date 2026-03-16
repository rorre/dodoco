package main

import (
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"
)

type Proxy struct {
	Transport *http.Transport
	Rules     *RuleEngine
	Username  string
	Password  string
}

func New(rules *RuleEngine) *Proxy {
	return &Proxy{
		Transport: &http.Transport{
			DialContext:           (&net.Dialer{Timeout: 30 * time.Second}).DialContext,
			TLSHandshakeTimeout:   10 * time.Second,
			ResponseHeaderTimeout: 30 * time.Second,
			IdleConnTimeout:       90 * time.Second,
		},
		Rules: rules,
	}
}

func (p *Proxy) checkProxyAuth(r *http.Request) bool {
	auth := r.Header.Get("Proxy-Authorization")
	const prefix = "Basic "
	if !strings.HasPrefix(auth, prefix) {
		return false
	}
	decoded, err := base64.StdEncoding.DecodeString(auth[len(prefix):])
	if err != nil {
		return false
	}
	user, pass, ok := strings.Cut(string(decoded), ":")
	if !ok {
		return false
	}
	return user == p.Username && pass == p.Password
}

func (p *Proxy) ListenAndServe(addr string) error {
	srv := &http.Server{
		Addr:    addr,
		Handler: p,
	}
	return srv.ListenAndServe()
}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if p.Username != "" && !p.checkProxyAuth(r) {
		w.Header().Set("Proxy-Authenticate", `Basic realm="dodoco"`)
		httpError(w, "Proxy authentication required", http.StatusProxyAuthRequired)
		return
	}
	r.Header.Del("Proxy-Authorization")

	if r.Method == http.MethodConnect {
		// This is for HTTPS proxy
		p.handleConnect(w, r)
	} else {
		p.handleHTTP(w, r)
	}
}

func (p *Proxy) dialForHost(host string) (DialContextFunc, error) {
	hostname, _, err := net.SplitHostPort(host)
	if err != nil {
		hostname = host
	}

	if p.Rules != nil {
		if matched := p.Rules.Find(hostname); matched != nil {
			log.Printf("rule matched for %s: iface=%q dns=%q", hostname, matched.TargetInterface, matched.TargetDNS)
			if matched.TargetInterface != "" {
				iface, err := net.InterfaceByName(matched.TargetInterface)
				if err != nil {
					return nil, fmt.Errorf("interface %q not found", matched.TargetInterface)
				}
				if iface.Flags&net.FlagUp == 0 {
					return nil, fmt.Errorf("interface %q is down", matched.TargetInterface)
				}
			}
			return matched.Dialer(30 * time.Second)
		}
	}

	d := &net.Dialer{Timeout: 30 * time.Second}
	return d.DialContext, nil
}

func (p *Proxy) handleConnect(w http.ResponseWriter, r *http.Request) {
	d, err := p.dialForHost(r.Host)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadGateway)
		return
	}

	dest, err := d(r.Context(), "tcp", r.Host)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer dest.Close()

	hj, ok := w.(http.Hijacker)
	if !ok {
		httpError(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	client, _, err := hj.Hijack()
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer client.Close()

	client.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	go func() {
		// Client -> Dest
		io.Copy(dest, client)
		if tc, ok := dest.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
	}()
	// Dest -> Client
	io.Copy(client, dest)
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		httpError(w, "missing host in request URI", http.StatusBadRequest)
		return
	}

	r.RequestURI = ""

	dialFn, err := p.dialForHost(r.URL.Host)
	if err != nil {
		httpError(w, err.Error(), http.StatusBadGateway)
		return
	}
	transport := &http.Transport{
		DialContext:           dialFn,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 30 * time.Second,
	}

	resp, err := transport.RoundTrip(r)
	if err != nil {
		log.Printf("upstream error: %v", err)
		httpError(w, err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)
}

func httpError(w http.ResponseWriter, message string, code int) {
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(code)
	fmt.Fprintf(
		w,
		`<!DOCTYPE html>
			<html><head><title>%d %s</title></head>
			<body>
				<h1>%d %s</h1>
				<p>%s</p>
				<p>Dodoco Proxy</p>
			</body>
		</html>`,
		code, http.StatusText(code),
		code, http.StatusText(code),
		message,
	)
}

func copyHeaders(dst, src http.Header) {
	for k, vs := range src {
		for _, v := range vs {
			dst.Add(k, v)
		}
	}
}
