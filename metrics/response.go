package metrics

import "github.com/miekg/dns"

type WithResponseOrError struct {
	response  *dns.Msg
	collector *Collector
	error     error
}

func (c *WithResponseOrError) GetMetrics() *Result {
	return fromCollector(c.collector)
}

func (c *WithResponseOrError) GetError() error {
	return c.error
}

func (c *WithResponseOrError) GetResponse() *dns.Msg {
	return c.response
}
