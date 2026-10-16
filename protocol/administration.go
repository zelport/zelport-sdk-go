package protocol

import (
	"errors"
	"net"
	"net/url"
	"strconv"
	"strings"
)

const Application = "application"
const Administration = "administration"

type ServiceLink struct {
	ServiceID string `json:"service_id"`
	URL       string `json:"url"`
}
type AdminOpen struct {
	Authority    string        `json:"authority"`
	ServiceLinks []ServiceLink `json:"service_links"`
}

func ReservedDomain(host string) bool {
	return host == "zelport.localhost" || strings.HasSuffix(host, ".zelport.localhost")
}

// AdminAuthority only accepts a single DNS label in the reserved namespace.
func AdminAuthority(authority string) (string, string, error) {
	host, port := authority, "80"
	if strings.Contains(authority, ":") {
		var e error
		host, port, e = net.SplitHostPort(authority)
		if e != nil {
			return "", "", e
		}
	}
	n, e := strconv.Atoi(port)
	label := strings.TrimSuffix(host, ".zelport.localhost")
	if e != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port || !ValidDomain(host) || !strings.HasSuffix(host, ".zelport.localhost") || strings.Contains(label, ".") || host != strings.ToLower(host) {
		return "", "", errors.New("invalid administration authority")
	}
	return host, port, nil
}
func (o OpenRequest) Validate() error {
	if !ValidID(o.ServiceID) || o.Authority == "" {
		return errors.New("invalid service request")
	}
	switch o.Kind {
	case Application:
		if o.Admin != nil {
			return errors.New("application cannot carry administration context")
		}
	case Administration:
		if o.Admin == nil || o.Trace != "" {
			return errors.New("missing or chained administration context")
		}
		_, port, e := AdminAuthority(o.Admin.Authority)
		if e != nil {
			return e
		}
		if len(o.Admin.ServiceLinks) > MaxServices {
			return errors.New("too many service links")
		}
		seen := map[string]bool{}
		for _, l := range o.Admin.ServiceLinks {
			u, e := url.Parse(l.URL)
			if e != nil || u.Scheme != "http" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" || (u.Path != "" && u.Path != "/") || !ValidDomain(u.Hostname()) || ReservedDomain(u.Hostname()) || !ValidID(l.ServiceID) || seen[l.ServiceID] {
				return errors.New("invalid service link")
			}
			p := u.Port()
			if p == "" {
				p = "80"
			}
			if p != port {
				return errors.New("service link port mismatch")
			}
			seen[l.ServiceID] = true
		}
	default:
		return errors.New("unknown service kind")
	}
	return nil
}
