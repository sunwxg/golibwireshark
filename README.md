# golibwireshark
[![GoDoc](http://godoc.org/github.com/sunwxg/golibwireshark?status.svg)](http://godoc.org/github.com/sunwxg/golibwireshark)

Package golibwireshark use libwireshark library to decode pcap file and analyse dissection data.

###Dependencies
* libwireshark library (I tested on version 1.12.7)

* libglib2.0

###Install
- ubuntu
```
apt-get install libwireshark-dev libglib2.0-dev libwiretap-dev libwsutil-dev
go get github.com/sunwxg/golibwireshark

cd  ${GOPATH}/src/github.com/sunwxg
cp include/cfile.h $(pkg-config --variable=includedir wireshark)/epan/

go build
go test
```
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

	if _, ok := p.IsKey(key); ok {
		p.WriteToFile()
	}

	p.FreePacket()
}
```
