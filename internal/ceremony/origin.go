package ceremony

import (
	"fmt"
	"net/url"
	"strings"
)

// NormalizeOrigins validates the allowed origins and returns them in the
// canonical form a browser writes in clientDataJSON (docs/api.md, Origin
// check): lowercase scheme and host, no default port, no trailing slash.
func NormalizeOrigins(origins []string) ([]string, error) {
	if len(origins) == 0 {
		return nil, fmt.Errorf("no allowed origin")
	}
	out := make([]string, 0, len(origins))
	for _, o := range origins {
		n, err := normalizeOrigin(o)
		if err != nil {
			return nil, fmt.Errorf("origin %q: %w", o, err)
		}
		out = append(out, n)
	}
	return out, nil
}

func normalizeOrigin(o string) (string, error) {
	for _, r := range o {
		if r > 0x7e || r < 0x21 {
			return "", fmt.Errorf("non-ASCII or blank character; write IDN hosts in punycode")
		}
	}
	if strings.Contains(o, "%") {
		return "", fmt.Errorf("percent-encoding is not allowed")
	}
	u, err := url.Parse(o)
	if err != nil {
		return "", err
	}
	if u.Opaque != "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(o, "#") {
		return "", fmt.Errorf("must be scheme://host[:port]")
	}
	if u.Path != "" && u.Path != "/" {
		return "", fmt.Errorf("must have no path")
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if host == "" {
		return "", fmt.Errorf("must be scheme://host[:port]")
	}
	switch scheme {
	case "https":
	case "http":
		if host != "localhost" && host != "127.0.0.1" {
			return "", fmt.Errorf("http is allowed for localhost and 127.0.0.1 only")
		}
	default:
		return "", fmt.Errorf("scheme must be https")
	}
	if (scheme == "https" && port == "443") || (scheme == "http" && port == "80") {
		port = ""
	}
	if port != "" {
		host += ":" + port
	}
	return scheme + "://" + host, nil
}

// withinRPID reports whether origin's host is rpID or one of its subdomains.
func withinRPID(origin, rpID string) bool {
	u, err := url.Parse(origin)
	if err != nil {
		return false
	}
	h := u.Hostname()
	return h == rpID || strings.HasSuffix(h, "."+rpID)
}

// --- Change History -------------------------------------------------------
// | PR     | Summary                                                       |
// |--------|---------------------------------------------------------------|
// | #12    | normalisation of the allowed origins                          |
