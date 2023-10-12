module github.com/hiddify/ray2sing

go 1.21.1

require (
	github.com/sagernet/sing v0.2.14-0.20231011040419-49f5dfd767e1
	github.com/sagernet/sing-box v1.5.3
)

require (
	github.com/miekg/dns v1.1.56 // indirect
	github.com/sagernet/sing-dns v0.1.10 // indirect
	golang.org/x/mod v0.12.0 // indirect
	golang.org/x/net v0.16.0 // indirect
	golang.org/x/sys v0.13.0 // indirect
	golang.org/x/tools v0.13.0 // indirect
)

replace github.com/sagernet/sing-box => github.com/hiddify/hiddify-sing-box v1.4.0-rc.3.0.20231012214115-1c5e9d3adbd1
