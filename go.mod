module github.com/hiddify/ray2sing

go 1.21.4

toolchain go1.22.3

require (
	github.com/sagernet/sing v0.4.3
	github.com/sagernet/sing-box v1.8.9
	github.com/spf13/cobra v1.8.0
	github.com/xtls/xray-core v1.8.21
)

require (
	github.com/andybalholm/brotli v1.1.0 // indirect
	github.com/cloudflare/circl v1.4.0 // indirect
	github.com/dgryski/go-metro v0.0.0-20211217172704-adc40b04c140 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/pprof v0.0.0-20240528025155-186aa0362fba // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/klauspost/compress v1.17.8 // indirect
	github.com/klauspost/cpuid/v2 v2.2.7 // indirect
	github.com/logrusorgru/aurora v2.0.3+incompatible // indirect
	github.com/miekg/dns v1.1.62 // indirect
	github.com/onsi/ginkgo/v2 v2.19.0 // indirect
	github.com/pires/go-proxyproto v0.8.0 // indirect
	github.com/quic-go/qpack v0.4.0 // indirect
	github.com/quic-go/quic-go v0.46.0 // indirect
	github.com/refraction-networking/utls v1.6.7 // indirect
	github.com/riobard/go-bloom v0.0.0-20200614022211-cdc8013cb5b3 // indirect
	github.com/sagernet/sing-dns v0.2.3 // indirect
	github.com/sagernet/sing-shadowsocks v0.2.7 // indirect
	github.com/seiflotfy/cuckoofilter v0.0.0-20240715131351-a2f2c23f1771 // indirect
	github.com/spf13/pflag v1.0.5 // indirect
	github.com/v2fly/ss-bloomring v0.0.0-20210312155135-28617310f63e // indirect
	github.com/xtls/reality v0.0.0-20240712055506-48f0b2d5ed6d // indirect
	go.uber.org/mock v0.4.0 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/crypto v0.28.0 // indirect
	golang.org/x/exp v0.0.0-20240531132922-fd00a4e0eefc // indirect
	golang.org/x/mod v0.18.0 // indirect
	golang.org/x/net v0.30.0 // indirect
	golang.org/x/sync v0.8.0 // indirect
	golang.org/x/sys v0.26.0 // indirect
	golang.org/x/text v0.19.0 // indirect
	golang.org/x/tools v0.22.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20240814211410-ddb44dafa142 // indirect
	google.golang.org/grpc v1.67.1 // indirect
	google.golang.org/protobuf v1.35.1 // indirect
	lukechampine.com/blake3 v1.3.0 // indirect
)

replace github.com/sagernet/sing-box => github.com/hiddify/hiddify-sing-box v1.8.9-0.20240928213625-7b79bf0c814d

replace github.com/xtls/xray-core => github.com/hiddify/xray-core v0.0.0-20241110202159-0fd7ffea9361
