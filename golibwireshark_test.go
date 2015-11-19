package golibwireshark_test

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/sunwxg/golibwireshark"
)

func TestMain(m *testing.M) {
	file := "1.pcap"
	err := golibwireshark.Init(file, "o.pcap")
	if err != nil {
		fmt.Println("open file error")
		os.Exit(1)
	}

	golibwireshark.CloseInputFile()
	golibwireshark.CloseOutputFile()

	m.Run()

	golibwireshark.Clean()
}

func TestIskey(t *testing.T) {
	file := "1.pcap"
	err := golibwireshark.ReOpenInputFile(file)
	if err != nil {
		t.Fatalf("%s", err)
	}

	var p golibwireshark.Packet

	p.GetPacket()
	if p.Edt == nil {
		fmt.Println("can't find packet")
		os.Exit(1)
	}

	key := "ip.addr"
	get, _ := p.IsKey(key)

	p.FreePacket()
	golibwireshark.CloseInputFile()

	wanted := []string{"10.128.229.6", "10.128.228.50"}
	if get[0] != wanted[0] {
		t.Fatalf("wanted: (%s), get: (%s)", wanted[0], get[0])
	}
	if get[1] != wanted[1] {
		t.Fatalf("wanted: (%s), get: (%s)", wanted[1], get[1])
	}

}

func TestGetField(t *testing.T) {
	file := "1.pcap"
	err := golibwireshark.ReOpenInputFile(file)
	if err != nil {
		t.Fatalf("%s", err)
	}

	var p golibwireshark.Packet

	p.GetPacket()
	if p.Edt == nil {
		fmt.Println("can't find packet")
		os.Exit(1)
	}

	buf := make([]byte, 100, 200)
	w := bytes.NewBuffer(buf)

	if p.GetField("ip") {
		fmt.Fprintln(w, p)
	}

	p.FreePacket()
	golibwireshark.CloseInputFile()

	len := w.Len()
	wanted_len := 662
	if len != wanted_len {
		t.Fatalf("wanted: (%d), get: (%d)", wanted_len, len)
	}
}

func TestWriteToFile(t *testing.T) {
	file := "1.pcap"
	err := golibwireshark.ReOpenInputFile(file)
	if err != nil {
		t.Fatalf("%s", err)
	}

	err = golibwireshark.ReOpenOutputFile("o.pcap")
	if err != nil {
		t.Fatalf("%s", err)
	}

	var p golibwireshark.Packet

	p.GetPacket()
	if p.Edt == nil {
		fmt.Println("can't find packet")
		os.Exit(1)
	}

	err = p.WriteToFile()
	if err != nil {
		t.Errorf("%s", err)
	}

	p.FreePacket()
	golibwireshark.CloseInputFile()
	golibwireshark.CloseOutputFile()
}
