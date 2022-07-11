module github.com/mgranderath/dnsperf

go 1.16

replace github.com/lucas-clemente/quic-go => ./replacement_modules/quic-go

require (
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/joomcode/errorx v1.0.3
	github.com/lucas-clemente/quic-go v0.21.2
	github.com/miekg/dns v1.1.40
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20220624214902-1bab6f366d9e
	golang.org/x/tools v0.1.7 // indirect
)
