package main

import (
	"fmt"
	natpmp "github.com/jackpal/go-nat-pmp"
	"net"
	"time"
)

func main() {

	localhost := net.ParseIP("127.0.0.1")

	client := natpmp.NewClientWithTimeout(localhost, 1*time.Second)

	result, err := client.AddPortMapping("udp", 4242, 0, 120)
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Printf("Result %v\n", result)

	//response, err := client.GetExternalAddress()
	//if err != nil {
	//	fmt.Println(err)
	//	return
	//}
	//fmt.Printf("External IP address: %v\n", response.ExternalIPAddress)
}
