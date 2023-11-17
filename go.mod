module github.com/hiddify/ray2sing

go 1.21.1

require (
	github.com/sagernet/sing v0.2.18-0.20231108041402-4fbbd193203c
	github.com/sagernet/sing-box v1.5.3
)

require (
	github.com/miekg/dns v1.1.56 // indirect
	github.com/sagernet/sing-dns v0.1.10 // indirect
	golang.org/x/mod v0.13.0 // indirect
	golang.org/x/net v0.18.0 // indirect
	golang.org/x/sys v0.14.0 // indirect
	golang.org/x/tools v0.14.0 // indirect
)

replace github.com/sagernet/sing-box => github.com/hiddify/hiddify-sing-box v1.4.0-rc.3.0.20231117161453-c3f0a30db24b
