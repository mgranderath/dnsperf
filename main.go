package main

import (
	"crypto/tls"
	"dnsperf/clients"
	"encoding/json"
	"github.com/miekg/dns"
	"log"

	"os"
	"time"
)

func main() {
	rrType := dns.TypeA
	timeout := 10

	opts := clients.Options{
		Timeout: time.Duration(timeout) * time.Second,
		TLSOptions: &clients.TLSOptions{
			MinVersion:         tls.VersionTLS10,
			MaxVersion:         tls.VersionTLS13,
			InsecureSkipVerify: false,
		},
		QuicOptions: &clients.QuicOptions{
			AllowedVersions: []string{clients.VersionQuic00, clients.VersionQuic01, clients.VersionQuic02},
		},
	}

	u, err := clients.AddressToClient("tls://dns.google", opts)
	if err != nil {
		log.Fatalf("Cannot create an upstream: %s", err)
	}

	req := dns.Msg{}
	req.Id = dns.Id()
	req.RecursionDesired = true
	req.Question = []dns.Question{
		{Name: "test.com" + ".", Qtype: rrType, Qclass: dns.ClassINET},
	}

	reply := u.Exchange(&req)
	if reply.GetError() != nil {
		log.Printf("Cannot make the DNS request: %s\n", reply.GetError())
	}

	b, err := json.MarshalIndent(reply.GetMetrics(), "", "  ")
	if err != nil {
		log.Fatalf("Cannot marshal json: %s", err)
	}

	os.Stdout.WriteString(string(b) + "\n")

	c, err := json.MarshalIndent(reply.GetResponse(), "", "  ")
	if err != nil {
		log.Fatalf("Cannot marshal json: %s", err)
	}

	os.Stdout.WriteString(string(c) + "\n")
}
