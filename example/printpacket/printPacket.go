package main

import (
	"fmt"

	"github.com/sunwxg/golibwireshark"
)

func main() {
	file := "../../1.pcap"

	err := golibwireshark.Init(file, "")
	if err != nil {
		fmt.Printf("open file failed\n")
		return
	}
	defer golibwireshark.Clean()

	var p golibwireshark.Packet

	for {
		p.GetPacket()
		if p.Edt == nil {
			break
		}

		fmt.Println(p)

		p.FreePacket()

	}
}
