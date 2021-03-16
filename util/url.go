package util

import (
	"fmt"
	"github.com/joomcode/errorx"
	"net"
	"net/url"
)

func ResolveURLToIP(unresolved *url.URL) ([]string, error) {
	host, port, err := net.SplitHostPort(unresolved.Host)
	if err != nil {
		return nil, fmt.Errorf("bootstrapper requires port in address %s", unresolved.String())
	}

	ip := net.ParseIP(host)
	if ip != nil {
		// ip is already resolved
		resolverAddress := net.JoinHostPort(host, port)
		return []string{resolverAddress}, nil
	}

	ips, err := net.LookupIP(host)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to lookup %s", host)
	}

	resolved := []string{}
	for _, addr := range ips {
		if addr.To4() == nil && addr.To16() == nil {
			continue
		}

		resolved = append(resolved, net.JoinHostPort(addr.String(), port))
	}

	return resolved, nil
}
