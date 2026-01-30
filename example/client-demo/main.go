package main

import (
	"fmt"
	"github.com/stsg/go-rndc"
)

func main() {
	rndc.SetLevelByString("error")

	client, err := rndc.NewRNDCClient("192.168.196.170:953", "hmac-sha256", "xRmH2XdFcDqWO91pYhiCwlZmWnaSO8EleBFu1uz8d3g=")
	if err != nil {
		panic(err)
	}

	resp, err := client.Call("sync test123.com")
	if err != nil {
		panic(err)
	}

	fmt.Printf("response: %s\n", resp)

	fmt.Printf("cmd: %s\n", resp.Data.Type)

	fmt.Printf("result: %s\n", resp.Data.Result)

	fmt.Printf("text: %s\n", resp.Data.Text)

	fmt.Printf("err: %s\n", resp.Data.Err)
}
