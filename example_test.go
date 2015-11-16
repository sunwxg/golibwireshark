package golibwireshark_test

import (
	"fmt"

	"github.com/sunwxg/golibwireshark"
)

func Example() {
	file := "1.pcap"
	outfile := "o.pcap"
	key := "ip.addr"

	err := golibwireshark.Init(file, outfile)
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

		if v := p.Iskey(key); v != "" {
			p.WriteToFile()
		}

		p.FreePacket()
	}
}
