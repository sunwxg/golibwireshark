/*
Package golibwireshark use libwireshark library to decode pcap file and analyse dissection data.
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

//Init initializing the dissection. If opening inputfile or savefile fail,
//return err. After dissection finish, should use Clean() to end the dissection.
func Init(inputfile, outputfile string) error {
	var err C.int

	if outputfile == "" {
		err = C.init(C.CString(inputfile), nil)
	} else {
		err = C.init(C.CString(inputfile), C.CString(outputfile))
	}

	if err != 0 {
		return fmt.Errorf("can't open file")
	}
	return nil
}

//Clean to end the dissection.
func Clean() {

	C.clean()
}

//ReOpenInputFile open a new input file after CloseInputFile.
//If open file failed, return error.
func ReOpenInputFile(filename string) error {
	var err C.int

	err = C.init_cfile(C.CString(filename))
	if err != 0 {
		return fmt.Errorf("can't open file")
	}
	return nil
}

//ReOpenOutputFile open a new output file after CloseOutputFile.
//if open file failed, return error.
func ReOpenOutputFile(filename string) error {
	var err C.int

	err = C.init_pdh(C.CString(filename))
	if err != 0 {
		return fmt.Errorf("can't create output file")
	}
	return nil

}

//CloseInputFile close input file. Using ReOpenInputFile to open a new input file.
func CloseInputFile() {
	C.clean_cfile()
}

//CloseOutputFile close output file. Using ReOpenOutputFile to open a new output file.
func CloseOutputFile() {
	C.clean_pdh()
}

//IsKey find a key in packet dissection data. If key exists, ok=ture,
//value is key value, otherwise ok=false.
func (p Packet) IsKey(key string) (values []string, ok bool) {
	finfoArray := C.get_field_values(p.Edt, C.CString(key))
	defer C.g_ptr_array_free(finfoArray, 1)

	if finfoArray != nil {
		for i := 0; i < int(finfoArray.len); i++ {
			finfo := C.g_ptr_array_data(finfoArray, C.int(i))
			value := C.finfo_to_value(unsafe.Pointer(finfo))
			values = append(values, C.GoString(value))
		}
	}

	if len(values) == 0 {
		return values, false
	}
	return values, true
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

//WriteToFile write a packet to file. If Output file are not initialized,
//return error.
func (p *Packet) WriteToFile() error {
	if i := C.write_to_file(); i == 0 {
		return nil
	} else if i == 1 {
		return fmt.Errorf("output file isn't opened")
	}
	return nil
}
