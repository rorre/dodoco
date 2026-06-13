package proxy

import (
	"bufio"
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"regexp"
	"strings"
	"time"
)

type Proxy struct {
	Transport *http.Transport
	Rules     *RuleEngine
	Username  string
	Password  string
	mitm      *mitmConfig
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
	hostname, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		hostname = r.Host
	}

	var matched *Rule
	if p.Rules != nil {
		matched = p.Rules.Find(hostname)
	}

	// If there are NO modify rules for a domain, then revert to tunneling and using transparent proxy
	if matched == nil || len(matched.ModifyResponse) == 0 || p.mitm == nil {
		p.handleTransparentConnect(w, r)
		return
	}

	p.handleMITM(w, r, matched)
}

func (p *Proxy) handleTransparentConnect(w http.ResponseWriter, r *http.Request) {
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

func (p *Proxy) handleMITM(w http.ResponseWriter, r *http.Request, rule *Rule) {
	cert, err := p.getCertForHost(r.Host)
	if err != nil {
		httpError(w, "failed to generate cert: "+err.Error(), http.StatusInternalServerError)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		httpError(w, "hijacking not supported", http.StatusInternalServerError)
		return
	}

	clientConn, _, err := hj.Hijack()
	if err != nil {
		httpError(w, err.Error(), http.StatusInternalServerError)
		return
	}
	defer clientConn.Close()

	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
	}
	tlsClientConn := tls.Server(clientConn, tlsConfig)
	if err := tlsClientConn.Handshake(); err != nil {
		log.Printf("TLS handshake with client failed: %v", err)
		return
	}
	defer tlsClientConn.Close()

	// Dial to destination
	dialFn, err := p.dialForHost(r.Host)
	if err != nil {
		log.Printf("failed to dial destination %s: %v", r.Host, err)
		return
	}

	reader := bufio.NewReader(tlsClientConn)
	for {
		req, err := http.ReadRequest(reader)
		if err != nil {
			if err != io.EOF {
				log.Printf("error reading request from %s: %v", r.Host, err)
			}
			return
		}

		// Prepare request to upstream
		req.URL.Scheme = "https"
		req.URL.Host = r.Host
		req.RequestURI = ""

		// If we have modification rules, we need to ensure we can decompress the response.
		// By deleting Accept-Encoding, http.Transport will request gzip and decompress it automatically.
		if len(rule.ModifyResponse) > 0 {
			req.Header.Del("Accept-Encoding")
		}

		transport := &http.Transport{
			DialContext: dialFn,
		}

		resp, err := transport.RoundTrip(req)
		if err != nil {
			log.Printf("upstream error for %s: %v", r.Host, err)
			return
		}

		// Apply modification rules
		p.modifyResponse(resp, rule)

		if err := resp.Write(tlsClientConn); err != nil {
			log.Printf("error writing response to client: %v", err)
			return
		}
		resp.Body.Close()
	}
}

func (p *Proxy) modifyResponse(resp *http.Response, rule *Rule) {
	if len(rule.ModifyResponse) == 0 {
		return
	}

	// Only modify text-based responses for safety
	contentType := resp.Header.Get("Content-Type")
	if !strings.Contains(contentType, "text") && !strings.Contains(contentType, "json") && !strings.Contains(contentType, "javascript") && !strings.Contains(contentType, "xml") {
		return
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("failed to read response body: %v", err)
		return
	}
	resp.Body.Close()

	newBody := body
	for _, m := range rule.ModifyResponse {
		if m.IsRegex {
			re, err := regexp.Compile(m.Search)
			if err != nil {
				log.Printf("invalid regex %q: %v", m.Search, err)
				continue
			}
			newBody = re.ReplaceAll(newBody, []byte(m.Replace))
		} else {
			newBody = bytes.ReplaceAll(newBody, []byte(m.Search), []byte(m.Replace))
		}
	}

	resp.Body = io.NopCloser(bytes.NewReader(newBody))
	resp.ContentLength = int64(len(newBody))
	resp.Header.Set("Content-Length", fmt.Sprint(len(newBody)))
	// Remove Content-Encoding as we might have invalidated it (e.g. gzip)
	resp.Header.Del("Content-Encoding")
}

func (p *Proxy) handleHTTP(w http.ResponseWriter, r *http.Request) {
	if r.URL.Host == "" {
		httpError(w, "missing host in request URI", http.StatusBadRequest)
		return
	}

	r.RequestURI = ""

	hostname, _, err := net.SplitHostPort(r.URL.Host)
	if err != nil {
		hostname = r.URL.Host
	}

	var matchedRule *Rule
	if p.Rules != nil {
		matchedRule = p.Rules.Find(hostname)
	}

	if matchedRule != nil && len(matchedRule.ModifyResponse) > 0 {
		r.Header.Del("Accept-Encoding")
	}

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

	if matchedRule != nil {
		p.modifyResponse(resp, matchedRule)
	}

	copyHeaders(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	io.Copy(w, resp.Body)

	resp.Body.Close()
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
