package urlguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

var (
	ErrScheme     = errors.New("only http/https allowed")
	ErrHost       = errors.New("missing host")
	ErrUserinfo   = errors.New("userinfo not allowed")
	ErrPrivateIP  = errors.New("destination is private/reserved")
	ErrNotAllowed = errors.New("host not on allowlist")
)

type Config struct {
	// Optional domain allowlist. Exact host match or subdomain of an entry.
	AllowHosts []string
	Timeout    time.Duration
	MaxHops    int // redirects
}

func DefaultConfig() Config { return Config{Timeout: 5 * time.Second, MaxHops: 3} }

func ParseAndValidate(raw string) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil {
		return nil, err
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return nil, ErrScheme
	}
	if u.Host == "" {
		return nil, ErrHost
	}
	if u.User != nil {
		return nil, ErrUserinfo
	}
	return u, nil
}

func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return true
	}
	if ip.IsLoopback() || ip.IsUnspecified() || ip.IsMulticast() {
		return true
	}
	// IPv4 private/link-local/CGN
	if v4 := ip.To4(); v4 != nil {
		switch {
		case v4[0] == 10:
			return true
		case v4[0] == 172 && v4[1] >= 16 && v4[1] <= 31:
			return true
		case v4[0] == 192 && v4[1] == 168:
			return true
		case v4[0] == 169 && v4[1] == 254: // link-local
			return true
		case v4[0] == 127: // loopback (already covered)
			return true
		case v4[0] == 100 && (v4[1] >= 64 && v4[1] <= 127): // CGNAT 100.64/10
			return true
		}
		return false
	}
	// IPv6: loopback ::1 covered; Unique local fc00::/7, link-local fe80::/10
	if ip.IsLoopback() {
		return true
	}
	if ip.IsLinkLocalUnicast() || ip.IsInterfaceLocalMulticast() || ip.IsLinkLocalMulticast() {
		return true
	}
	// fc00::/7
	if len(ip) == net.IPv6len && (ip[0]&0xfe) == 0xfc {
		return true
	}
	return false
}

func hostAllowed(host string, allow []string) bool {
	if len(allow) == 0 {
		return true
	}
	host = strings.ToLower(host)
	for _, a := range allow {
		a = strings.ToLower(strings.TrimSpace(a))
		if a == "" {
			continue
		}
		if host == a || strings.HasSuffix(host, "."+a) {
			return true
		}
	}
	return false
}

func BuildSafeClient(cfg Config) *http.Client {
	if cfg.Timeout == 0 {
		cfg.Timeout = 5 * time.Second
	}
	if cfg.MaxHops <= 0 {
		cfg.MaxHops = 3
	}
	dialer := &net.Dialer{Timeout: cfg.Timeout}
	transport := &http.Transport{
		Proxy: http.ProxyFromEnvironment,
		DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(address)
			if err != nil {
				return nil, err
			}
			// DNS resolve and vet each IP
			ips, err := net.DefaultResolver.LookupIPAddr(ctx, host)
			if err != nil {
				return nil, err
			}
			for _, ip := range ips {
				if IsPrivateIP(ip.IP) {
					return nil, ErrPrivateIP
				}
			}
			if !hostAllowed(host, cfg.AllowHosts) {
				return nil, ErrNotAllowed
			}
			return dialer.DialContext(ctx, network, net.JoinHostPort(host, port))
		},
		ResponseHeaderTimeout: cfg.Timeout,
		IdleConnTimeout:       30 * time.Second,
	}
	client := &http.Client{
		Timeout:   cfg.Timeout,
		Transport: transport,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= cfg.MaxHops {
				return http.ErrUseLastResponse
			}
			// Re-validate each hop’s host/scheme
			if req.URL.Scheme != "http" && req.URL.Scheme != "https" {
				return ErrScheme
			}
			host := req.URL.Hostname()
			if !hostAllowed(host, cfg.AllowHosts) {
				return ErrNotAllowed
			}
			// Dialer will also DNS-check on connect
			return nil
		},
	}
	return client
}
