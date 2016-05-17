package main

import (
	"fmt"

	"github.com/sunwxg/golibwireshark"
)

func main() {
	file := "../../1.pcap"
	key := "ip.addr"

	golibwireshark.Init(file, "")
	defer golibwireshark.Clean()

	var p golibwireshark.Packet

	for {
		p.GetPacket()
		if p.Edt == nil {
			break
		}

		if valueList, ok := p.IsKey(key); ok {
			for _, v := range valueList {
				fmt.Printf("[%s] %s\n", key, v)
			}
		}

		p.FreePacket()

	}
}
