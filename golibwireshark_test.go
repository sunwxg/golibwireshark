package golibwireshark_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/sunwxg/golibwireshark"
)

func TestIsKey(t *testing.T) {
	file := "1.pcap"
	err := golibwireshark.Init(file, "o.pcap")
	if err != nil {
		t.Fatalf("%s", err)
	}

	var p golibwireshark.Packet

	p.GetPacket()
	if p.Edt == nil {
		t.Fatalf("don't find packet\n")
	}

	key := "ip.addr"
	get := p.Iskey(key)

	//fmt.Println(p)
	buf := make([]byte, 100, 200)
	w := bytes.NewBuffer(buf)

	if p.GetField("ip") {
		//fmt.Println(p)
		fmt.Fprintln(w, p)
	}

	err = p.WriteToFile()
	if err != nil {
		t.Errorf("%s", err)
	}

	p.FreePacket()

	golibwireshark.Clean()

	wanted := "10.128.229.6"
	if get != wanted {
		t.Fatalf("wanted: (%s), get: (%s)", wanted, get)
	}

	//fmt.Println(w)
	len := w.Len()
	wanted_len := 662
	if len != wanted_len {
		t.Fatalf("wanted: (%d), get: (%d)", wanted_len, len)
	}
}
