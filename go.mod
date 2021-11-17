module github.com/Lucapaulo/dnsperf

go 1.16

replace github.com/lucas-clemente/quic-go => "./replacement_modules/quic-go"

require (
	github.com/fsnotify/fsnotify v1.5.1 // indirect
	github.com/joomcode/errorx v1.0.3
	github.com/lucas-clemente/quic-go v0.21.2
	github.com/miekg/dns v1.1.40
	golang.org/x/crypto v0.0.0-20210921155107-089bfa567519 // indirect
	golang.org/x/net v0.0.0-20210929193557-e81a3d93ecf6
	golang.org/x/sys v0.0.0-20211003122950-b1ebd4e1001c // indirect
	golang.org/x/tools v0.1.7 // indirect
)
