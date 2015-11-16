# golibwireshark
[![GoDoc](http://godoc.org/github.com/sunwxg/golibwireshark?status.svg)](http://godoc.org/github.com/sunwxg/golibwireshark)

Package golibwireshark use libwireshark library to decode pcap file and analysis dissection data.

###Dependencies
libwireshark library (I tested on version 1.12.7)

###Install
>####ubuntu
>>apt-get install libwireshark-dev

###Examples
```go
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
