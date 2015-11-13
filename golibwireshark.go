package golibwireshark

/*
#cgo pkg-config: glib-2.0
#cgo LDFLAGS: -lwiretap -lwsutil -lwireshark
#cgo CFLAGS: -I.
#cgo CFLAGS: -I/usr/include/glib-2.0
#cgo CFLAGS: -I/usr/lib/x86_64-linux-gnu/glib-2.0/include
#cgo CFLAGS: -I/usr/include/wireshark
#cgo CFLAGS: -I/usr/include/wireshark/wiretap
#cgo CFLAGS: -I/home/home/person/wireshark-1.12.8

#include "lib.h"

*/
import "C"
import (
	"fmt"
	"unsafe"
)

type Packet struct {
	Edt   *C.struct_epan_dissect
	Field *C.struct__proto_node
}

func Init(filename, savefile string) error {
	var err C.int

	if savefile == "" {
		err = C.init(C.CString(filename), nil)
	} else {
		err = C.init(C.CString(filename), C.CString(savefile))
	}

	if err != 0 {
		return fmt.Errorf("can't open file")
	}
	return nil
}

func (p Packet) PrintXmlPacket() {

	C.print_xml_packet()
}

func Clean() {

	C.clean()
}

func (p Packet) Iskey(key string) (value string) {
	buf := C.get_field_value(p.Edt, C.CString(key))
	defer C.free(unsafe.Pointer(buf))

	value = C.GoString(buf)
	return value
}

func (p *Packet) GetPacket() {
	var edt *C.struct_epan_dissect
	edt = C.next_packet()
	if edt == nil {
		p.Edt = nil
	}
	p.Edt = edt
}

func (p *Packet) FreePacket() {
	C.free_packet(p.Edt)
}

func (p *Packet) GetField(key string) bool {
	p.Field = C.get_field(p.Edt, C.CString(key))
	if p.Field != nil {
		return true
	}
	return false
}

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

func (p *Packet) WriteToFile() error {
	if i := C.write_to_file(); i == 0 {
		return nil
	} else if i == 1 {
		return fmt.Errorf("output file isn't opened")
	}
	return nil
}
