/*
Package golibwireshark use libwireshark library to decode pcap file.
*/
package golibwireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -lwiretap -lwsutil -lwireshark
#cgo CFLAGS: -I.
#cgo CFLAGS: -I/usr/include/glib-2.0
#cgo CFLAGS: -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
#cgo CFLAGS: -I/usr/include/wireshark
#cgo CFLAGS: -I/usr/include/wireshark/wiretap
#cgo CFLAGS: -I./include

#include "./include/lib.h"

*/
import "C"
import (
	"fmt"
	"unsafe"
)

//Packet data index after dissection
type Packet struct {
	Edt   *C.struct_epan_dissect //packet data index after dissected
	Field *C.struct__proto_node  //packet field index
}

//Init initializing the dissection. If open inputfile or savefile fail,
//return err. After dissection finish, should use Clean() to end the dissection.
//Do it before GetPacket().
func Init(inputfile, savefile string) error {
	var err C.int

	if savefile == "" {
		err = C.init(C.CString(inputfile), nil)
	} else {
		err = C.init(C.CString(inputfile), C.CString(savefile))
	}

	if err != 0 {
		return fmt.Errorf("can't open file")
	}
	return nil
}

//PrintXMLPacket output the packet as XML format to stdout
func (p Packet) PrintXMLPacket() {

	C.print_xml_packet()
}

//Clean to end the dissection.
func Clean() {

	C.clean()
}

//Iskey find a key in packet dissection data. If key exists, return value,
//otherwise return "".
func (p Packet) Iskey(key string) (value string) {
	buf := C.get_field_value(p.Edt, C.CString(key))
	defer C.free(unsafe.Pointer(buf))

	value = C.GoString(buf)
	return value
}

//GetPacket get one packet data index which has been dissected. If no more
//packet to be dissected, Edt return nil.
//After analysing packet data, should use FreePacket() to free packet
//data.
func (p *Packet) GetPacket() {
	var edt *C.struct_epan_dissect
	edt = C.next_packet()
	if edt == nil {
		p.Edt = nil
	}
	p.Edt = edt
}

//FreePacket to release packet memory
func (p *Packet) FreePacket() {
	C.free_packet(p.Edt)
}

//GetField get field index by key. If key exists, return true, Field item equal index,
//otherwise return false and Field item equal nil.
func (p *Packet) GetField(key string) bool {
	p.Field = C.get_field(p.Edt, C.CString(key))
	if p.Field != nil {
		return true
	}
	return false
}

//String do human readable printout. If Field equal nil, print out the packet.
//If Field doesn't equal nil, print out the Field.
func (p Packet) String() string {
	var node *C.struct__proto_node
	var buf string

	if p.Field != nil {
		node = p.Field
		cbuf := C.print_node(node)
		defer C.free(unsafe.Pointer(cbuf))
		buf = C.GoString(cbuf)
	} else {
		node = (p.Edt).tree
		cbuf := C.print_packet(node)
		defer C.free(unsafe.Pointer(cbuf))
		buf = C.GoString(cbuf)
	}

	return buf
}

//WriteToFile write a packet to file. If savefile aren't be initialized,
//return error.
func (p *Packet) WriteToFile() error {
	if i := C.write_to_file(); i == 0 {
		return nil
	} else if i == 1 {
		return fmt.Errorf("output file isn't opened")
	}
	return nil
}
