package main

import (
	_ "embed"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/hiddify/ray2sing/ray2sing"
)

var examples = map[string][]string{
	"hysteria": {
		"hysteria://host:443?protocol=udp&auth=123456&peer=sni.domain&insecure=1&upmbps=100&downmbps=100&alpn=hysteria&obfs=xplus&obfsParam=123456#remarks",
	},
	"ssconf": {
		"ssconf://s3.amazonaws.com/beedynconprd/ng4lf90ip01zstlyle4r0t56x1qli4cvmt2ws6nh0kdz1jpgzyedogxt3mpxfbxi.json#BeePass",
	},
	"reality": {
		"vless://409f106a-b2f2-4416-b186-5429c9979cd9@54.38.144.4:2053?encryption=none&flow=&fp=chrome&pbk=SbVKOEMjK0sIlbwg4akyBg5mL5KZwwB-ed4eEE7YnRc&security=reality&serviceName=xyz&sid=&sni=discordapp.com&type=grpc#رایگان | REALITY | @EliV2ray | FR🇫🇷 | 0️⃣1️⃣",
	},
	"vless": {
		"vless://25da296e-1d96-48ae-9867-4342796cd742@172.67.149.95:443?encryption=none&fp=chrome&host=vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev&path=%2F%3Fed%3D2048&security=tls&sni=vless.229feb8b52a0e7e117ea76f8b591bcb3.workers.dev&type=ws#رایگان | VLESS | @Helix_Servers | US🇺🇸 | 0️⃣1️⃣",
	},
	"vmess": {
		"vmess://eyJhZGQiOiI1MS4xNjEuMTMwLjE3MyIsImFpZCI6IjAiLCJhbHBuIjoiIiwiZnAiOiIiLCJob3N0IjoiIiwiaWQiOiJkNDNlZTVlMy0xYjA3LTU2ZDctYjJlYS04ZDIyYzQ0ZmRjNjYiLCJuZXQiOiJ0Y3AiLCJwYXRoIjoiIiwicG9ydCI6IjgwODAiLCJzY3kiOiJjaGFjaGEyMC1wb2x5MTMwNSIsInNuaSI6IiIsInRscyI6IiIsInR5cGUiOiJub25lIiwidiI6IjIiLCJwcyI6Ilx1MDYzMVx1MDYyN1x1MDZjY1x1MDZhZlx1MDYyN1x1MDY0NiB8IFZNRVNTIHwgQFdhdGFzaGlfVlBOIHwgQVVcdWQ4M2NcdWRkZTZcdWQ4M2NcdWRkZmEgfCAwXHVmZTBmXHUyMGUzMVx1ZmUwZlx1MjBlMyJ9",
	},
	"ss": {
		"ss://Y2hhY2hhMjAtaWV0Zi1wb2x5MTMwNTp0T3dPeXZsWGlZNUFUSkFVT3BYTlBO@5.35.34.107:55990#%D8%B1%D8%A7%DB%8C%DA%AF%D8%A7%D9%86+%7C+SS+%7C+%40iP_CF+%7C+RU%F0%9F%87%B7%F0%9F%87%BA+%7C+0%EF%B8%8F%E2%83%A31%EF%B8%8F%E2%83%A3",
	},
	"tuic": {
		"tuic://3618921b-adeb-4bd3-a2a0-f98b72a674b1:dongtaiwang@108.181.24.7:23450?allow_insecure=1&alpn=h3&congestion_control=bbr&sni=www.google.com&udp_relay_mode=native#رایگان | TUIC | @V2rayCollector | CA🇨🇦 | 0️⃣1️⃣",
	},
	"hy2": {
		"hysteria2://letmein@example.com/?insecure=1&obfs=salamander&obfs-password=gawrgura&pinSHA256=deadbeef&sni=real.example.com",
	},
	"ssh": {
		"ssh://user:pass@server:22/?pk=pk&hk=hk",
	},
	"trojan": {
		"trojan://your_password@aws-ar-buenosaires-1.f1cflineb.com:443?host=aws-ar-buenosaires-1.f1cflineb.com&path=%2Ff1rocket&security=tls&sni=aws-ar-buenosaires-1.f1cflineb.com&type=ws#رایگان | TROJAN | @VmessProtocol | RELAY🚩 | 0️⃣1️⃣",
	},
	"wg": {
		"wg://[server]:222/?pk=[private_key]&local_address=10.0.0.2/24&peer_pk=[peer_public_key]&pre_shared_key=[pre_shared_key]&workers=[workers]&mtu=[mtu]&reserved=0,0,0",
	},
}

func main() {
	// Replace "path/to/your/config/file" with the actual path to your config file
	var configs string
	if len(os.Args) > 1 {
		if len(examples[os.Args[1]]) != 0 {
			configs = strings.Join(examples[os.Args[1]], "\n")
			fmt.Printf("%s\n", configs)
		} else {
			configs = strings.Join(os.Args[1:], "\n")
		}
	} else {
		configs = read()
	}
	clash_conf, err := ray2sing.Ray2Singbox(configs)
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	fmt.Printf("Parsed config: \n%+v\n", clash_conf)
	fmt.Printf("==============\n===========\n=============")

}

func read() string {
	url := "https://raw.githubusercontent.com/ImMyron/V2ray/main/V2ray.txt"

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching URL content:", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return ""
	}

	fmt.Println("URL Content:")
	fmt.Println(string(body))
	return string(body)
}
