package clients

import (
	"errors"
	"fmt"
	"github.com/joomcode/errorx"
	"github.com/mgranderath/dnsperf/metrics"
	"github.com/miekg/dns"
	"net/url"
	"strings"
)

type DnsClient interface {
	Exchange(m *dns.Msg) *metrics.WithResponseOrError
}

func AddressToClient(address string, options Options) (DnsClient, error) {
	if !strings.Contains(address, "://") {
		return nil, errors.New("not supported")
	}
	upstreamURL, err := url.Parse(address)
	if err != nil {
		return nil, errorx.Decorate(err, "failed to parse %s", address)
	}
	return urlToUpstream(upstreamURL, options)
}

func urlToUpstream(upstreamURL *url.URL, options Options) (DnsClient, error) {
	switch upstreamURL.Scheme {
	case "https":
		if upstreamURL.Port() == "" {
			// set default port
			upstreamURL.Host += ":443"
		}

		b, err := newBaseClient(upstreamURL, options)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}
		return &DoHClient{baseClient: b}, err
	case "tcp":
		if upstreamURL.Port() == "" {
			// set default port
			upstreamURL.Host += ":53"
		}
		b, err := newBaseClient(upstreamURL, options)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}
		return &DoTCPClient{baseClient: b}, err
	case "udp":
		if upstreamURL.Port() == "" {
			// set default port
			upstreamURL.Host += ":53"
		}
		b, err := newBaseClient(upstreamURL, options)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}
		return &DoUDPClient{baseClient: b}, err
	case "tls":
		if upstreamURL.Port() == "" {
			upstreamURL.Host += ":853"
		}
		b, err := newBaseClient(upstreamURL, options)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}
		return &DoTClient{baseClient: b}, err
	case "quic":
		if upstreamURL.Port() == "" {
			// https://tools.ietf.org/html/draft-ietf-dprive-dnsoquic-00#section-8.2.1
			// Early experiments MAY use port 784.  This port is marked in the IANA
			// registry as unassigned.
			upstreamURL.Host += ":784"
		}
		b, err := newBaseClient(upstreamURL, options)
		if err != nil {
			return nil, errorx.Decorate(err, "couldn't create tls bootstrapper")
		}
		return &DoQClient{baseClient: b}, err
	default:
		return nil, fmt.Errorf("unsupported URL scheme: %s", upstreamURL.Scheme)
	}
}
