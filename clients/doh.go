package clients

import (
	"context"
	"encoding/base64"
	"github.com/joomcode/errorx"
	"github.com/mgranderath/dnsperf/metrics"
	"github.com/miekg/dns"
	"golang.org/x/net/http2"
	"io/ioutil"
	"net"
	"net/http"
)

// WrappedTransport wraps the default http.Transport so that we can set the query finish time
type WrappedTransport struct {
	collector *metrics.Collector
	transport *http.Transport
}

func (w *WrappedTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	response, err := w.transport.RoundTrip(r)
	w.collector.QueryReceive()
	return response, err
}

// DoHMaxConnsPerHost controls the maximum number of connections per host.
const DoHMaxConnsPerHost = 1

type DoHClient struct {
	baseClient *baseClient
}

func (c *DoHClient) exchangeHTTPSClient(m *dns.Msg, client *http.Client, collector *metrics.Collector) (*dns.Msg, error) {
	buf, err := m.Pack()
	if err != nil {
		return nil, errorx.Decorate(err, "couldn't pack request msg")
	}

	// It appears, that GET requests are more memory-efficient with Golang
	// implementation of HTTP/2.
	requestURL := c.baseClient.URL.String() + "?dns=" + base64.RawURLEncoding.EncodeToString(buf)
	req, err := http.NewRequest("GET", requestURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/dns-message")

	collector.QuerySend()
	resp, err := client.Do(req)
	if resp != nil && resp.Body != nil {
		defer resp.Body.Close()
	}

	if err != nil {
		return nil, err
	}

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	collector.HTTPVersion(resp.Proto)
	if resp.StatusCode != http.StatusOK {
		return nil, err
	}
	response := dns.Msg{}
	err = response.Unpack(body)
	if err != nil {
		return nil, err
	}
	if response.Id != m.Id {
		err = dns.ErrId
	}

	collector.HTTPVersion(resp.Proto)

	collector.ExchangeFinished()
	return &response, err
}

func (c *DoHClient) Exchange(m *dns.Msg) *metrics.WithResponseOrError {
	collector := &metrics.Collector{}
	collector.ExchangeStarted()
	client := c.createClient(collector)
	reply, err := c.exchangeHTTPSClient(m, client, collector)
	if err != nil {
		return collector.WithError(err)
	}
	return collector.WithResponse(reply)
}

func (c *DoHClient) wrappedTLSDial(collector *metrics.Collector) func(context context.Context, network string, addr string) (net.Conn, error) {
	tlsDial := c.baseClient.getTLSDialContext(collector)

	return func(context context.Context, network string, addr string) (net.Conn, error) {
		conn, err := tlsDial(context, network, addr)
		collector.QuerySend()
		return conn, err
	}
}

func (c *DoHClient) createTransport(collector *metrics.Collector) *WrappedTransport {
	tlsConfig := c.baseClient.resolvedConfig

	transport := &http.Transport{
		TLSClientConfig:    tlsConfig,
		DisableCompression: true,
		DialTLSContext:     c.wrappedTLSDial(collector),
		MaxConnsPerHost:    DoHMaxConnsPerHost,
		MaxIdleConns:       1,
	}

	// It appears that this is important to explicitly configure transport to use HTTP2
	// Relevant issue: https://github.com/AdguardTeam/dnsproxy/issues/11
	http2.ConfigureTransports(transport) // nolint

	return &WrappedTransport{collector: collector, transport: transport}
}

func (c *DoHClient) createClient(collector *metrics.Collector) *http.Client {
	transport := c.createTransport(collector)

	client := &http.Client{
		Transport: transport,
		Timeout:   c.baseClient.options.Timeout,
		Jar:       nil,
	}

	return client
}
