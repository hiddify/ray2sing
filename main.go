package main

import (
	_ "embed"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"

	"github.com/hiddify/ray2sing/ray2sing"
)

func main() {
	// Replace "path/to/your/config/file" with the actual path to your config file
	clash_conf, err := ray2sing.Ray2Singbox(read())
	if err != nil {
		log.Fatalf("Failed to parse config: %v", err)
	}

	fmt.Printf("Parsed config: %+v\n", clash_conf)
	fmt.Printf("==============\n===========\n=============")

}

func read() string {
	url := "https://clean.alicivil.workers.dev/?ip=185.109.21.134&protocol=&count=100000000&url=https://sub.EndOfTheLine.cloud/subscribe?tkn=fd82ce20d1c10d1e27e548105"

	resp, err := http.Get(url)
	if err != nil {
		fmt.Println("Error fetching URL content:", err)
		return ""
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response body:", err)
		return ""
	}

	fmt.Println("URL Content:")
	fmt.Println(string(body))
	return string(body)
}
