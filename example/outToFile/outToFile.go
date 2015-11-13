package main

import (
	"fmt"
	"mypkg/golibwireshark"
)

func main() {
	file := "../../1.pcap"
	outfile := "o.pcap"

	err := golibwireshark.Init(file, outfile)
	if err != nil {
		fmt.Printf("open file failed\n")
		return
	}
	defer golibwireshark.Clean()

	//golibwireshark.PrintPacket()

	var p golibwireshark.Packet

	for {
		p.GetPacket()
		if p.Edt == nil {
			break
		}

		p.WriteToFile()

		p.FreePacket()

	}
}
