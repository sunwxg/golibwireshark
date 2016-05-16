# golibwireshark
[![GoDoc](http://godoc.org/github.com/sunwxg/golibwireshark?status.svg)](http://godoc.org/github.com/sunwxg/golibwireshark)

Package golibwireshark use libwireshark library to decode pcap file and analyse dissection data.

This package can only be used in OS linux with CPU x86_64.
If you want to use it on other CPU structure, you need compile library in libs folder from source code.

###Dependencies
* libwireshark library (version 1.12.8)

* libglib2.0

###Install
- ubuntu
```
apt-get install libglib2.0-dev
go get github.com/sunwxg/golibwireshark

cd $GOPATH/src/github.com/sunwxg/golibwireshark
cat libs/libwireshark.{00,01,02,03} > libs/libwireshark.so
chmod 775 libs/libwireshark.so

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
