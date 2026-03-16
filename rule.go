package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type Rule struct {
	HostRule        string `json:"hostRule"`
	TargetInterface string `json:"targetInterface,omitempty"`
	TargetDNS       string `json:"targetDNS,omitempty"`
}

func (r *Rule) Validate() error {
	if _, err := filepath.Match(r.HostRule, ""); err != nil {
		return fmt.Errorf("invalid hostRule glob %q: %w", r.HostRule, err)
	}
	return nil
}

func (r *Rule) Match(hostname string) bool {
	ok, _ := filepath.Match(r.HostRule, hostname)
	return ok
}

// Signature used by http.Transport.DialContext.
type DialContextFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (r *Rule) Dialer(timeout time.Duration) (DialContextFunc, error) {
	var control func(network, address string, c syscall.RawConn) error
	var ipv4, ipv6 net.IP

	if r.TargetInterface != "" {
		ifaceName := r.TargetInterface
		iface, err := net.InterfaceByName(ifaceName)
		if err != nil {
			return nil, fmt.Errorf("interface %q: %w", ifaceName, err)
		}
		addrs, err := iface.Addrs()
		if err != nil {
			return nil, fmt.Errorf("interface %q addrs: %w", ifaceName, err)
		}
		for _, a := range addrs {
			ip, _, _ := net.ParseCIDR(a.String())
			if ip == nil {
				continue
			}
			if ip.To4() != nil && ipv4 == nil {
				ipv4 = ip
			} else if ip.To4() == nil && ipv6 == nil {
				ipv6 = ip
			}
		}
		if ipv4 == nil && ipv6 == nil {
			return nil, fmt.Errorf("no addresses on interface %q", ifaceName)
		}

		control = func(network, address string, c syscall.RawConn) error {
			var sockErr error
			err := c.Control(func(fd uintptr) {
				// NOTE: this will require the binary to have CAP_NET_RAW capability
				sockErr = unix.BindToDevice(int(fd), ifaceName)
			})
			if err != nil {
				return err
			}
			return sockErr
		}
	}

	var resolver *net.Resolver
	if r.TargetDNS != "" {
		dnsAddr := r.TargetDNS
		if _, _, err := net.SplitHostPort(dnsAddr); err != nil {
			dnsAddr = net.JoinHostPort(dnsAddr, "53")
		}
		resolver = &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
				return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "udp", dnsAddr)
			},
		}
	}

	dialFn := func(ctx context.Context, network, address string) (net.Conn, error) {
		d := &net.Dialer{
			Timeout:  timeout,
			Control:  control,
			Resolver: resolver,
		}

		// If there is both ipv4 and ipv6 on this interface, then we decide which local
		// address to use based on the destination.
		// Though, ipv4 is preffered just for compatibility reason.
		if ipv4 != nil || ipv6 != nil {
			host, _, _ := net.SplitHostPort(address)
			dstIP := net.ParseIP(host)

			if dstIP != nil && dstIP.To4() == nil && ipv6 != nil {
				d.LocalAddr = &net.TCPAddr{IP: ipv6}
				network = "tcp6"
			} else if ipv4 != nil {
				d.LocalAddr = &net.TCPAddr{IP: ipv4}
				network = "tcp4"
			} else if ipv6 != nil {
				d.LocalAddr = &net.TCPAddr{IP: ipv6}
				network = "tcp6"
			}
		}

		return d.DialContext(ctx, network, address)
	}

	return dialFn, nil
}

type ruleTarget struct {
	TargetInterface string `json:"targetInterface,omitempty"`
	TargetDNS       string `json:"targetDNS,omitempty"`
}

type ruleFile struct {
	Rules map[string]ruleTarget `json:"rules"`
}

func LoadRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading rules file: %w", err)
	}

	var f ruleFile
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing rules file: %w", err)
	}

	rules := make([]Rule, 0, len(f.Rules))
	for host, target := range f.Rules {
		rules = append(rules, Rule{
			HostRule:        host,
			TargetInterface: target.TargetInterface,
			TargetDNS:       target.TargetDNS,
		})
	}
	return rules, nil
}

type RuleEngine struct {
	rules []Rule
}

func NewRuleEngine(rules []Rule) (*RuleEngine, error) {
	for i := range rules {
		if err := rules[i].Validate(); err != nil {
			return nil, err
		}
	}
	return &RuleEngine{rules: rules}, nil
}

func specificity(pattern string) int {
	// very naive, just check how much has matched to the right
	segments := strings.Split(pattern, ".")
	score := 0
	for i := len(segments) - 1; i >= 0; i-- {
		if strings.ContainsAny(segments[i], "*?") {
			break
		}
		score++
	}
	return score
}

func (e *RuleEngine) Find(hostname string) *Rule {
	var best *Rule
	bestScore := -1
	for i := range e.rules {
		if e.rules[i].Match(hostname) {
			s := specificity(e.rules[i].HostRule)
			if s > bestScore {
				bestScore = s
				best = &e.rules[i]
			}
		}
	}
	return best
}
