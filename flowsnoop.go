package main

/*
#include <arpa/inet.h>
#include <netinet/in.h>
*/

import "C"

import (
	"bytes"
	"encoding/binary"
	"fmt"
	bpf "github.com/aquasecurity/libbpfgo"
	"math/big"
	"net"
	"os"
	"time"
)

func okexit() {
	fmt.Fprintf(os.Stdout, "success\n")
	os.Exit(0)
}

func errexit(why error) {
	fmt.Fprintf(os.Stdout, "error: %s\n", why)
	os.Exit(1)
}

func errtimeout() {
	fmt.Fprintf(os.Stdout, "timeout\n")
	os.Exit(3)
}

// I have not packed the data struct shared among bpf and userland
// discover holes and paddings with: pahole -C struct_name ./binary
type _data struct {
	Comm      [16]byte // 00 - 16 : command (task_comm_len)
	Pid       uint32   // 16 - 20 : process id
	Uid       uint32   // 20 - 24 : user id
	Gid       uint32   // 24 - 28 : group id
	LoginUid  uint32   // 28 - 32 : real user (login/terminal)
	Family    uint8    // 32 - 33 : network family
	Proto     uint8    // 33 - 34 : protocol (sock.h: u8 older, u16 newer)
	SPort     uint16   // 34 - 36 : source port
	DPort     uint16   // 36 - 38 : dest port
	_         [2]byte  // 38 - 40 : -- (hole for cache align)
	SAddr     uint32   // 40 - 44 : source address
	SAddr6    [16]byte // 44 - 60 : source address (IPv6)
	DAddr     uint32   // 60 - 64 : dest address
	DAddr6    [16]byte // 64 - 80 : dest address (IPv6)
	TheSource uint8    // 80 - 81 : am I originating the packet ?
	_         [3]byte  // 81 - 84 : -- (padding, total = 84 bytes)
}

type data struct {
	SAddr uint32
	DAddr uint32
	SPort uint16
	DPort uint16
	Proto uint8
}

type gdata struct {
	SAddr string
	DAddr string
	SPort uint
	DPort uint
	Proto uint
}

type _gdata struct {
	Comm     string
	Pid      uint
	Uid      uint
	Gid      uint
	LoginUid uint
	Family   uint
	Proto    uint
	SPort    uint
	DPort    uint
	SAddr    string
	DAddr    string
}

// IPv4Int...
func IP4toInt(IPv4Address net.IP) int64 {
	IPv4Int := big.NewInt(0)
	IPv4Int.SetBytes(IPv4Address.To4())
	return IPv4Int.Int64()
}

//similar to Python's socket.inet_aton() function
//https://docs.python.org/3/library/socket.html#socket.inet_aton

func Pack32BinaryIP4(ip4Address string) string {
	ipv4Decimal := IP4toInt(net.ParseIP(ip4Address))

	buf := new(bytes.Buffer)
	err := binary.Write(buf, binary.BigEndian, uint32(ipv4Decimal))

	if err != nil {
		fmt.Println("Unable to write to buffer:", err)
	}

	// present in hexadecimal format
	result := fmt.Sprintf("%x", buf.Bytes())
	return result
}

func HexStringToNum(data string) int64 {
	n := new(big.Int)
	n.SetString(data, 16)
	return n.Int64()
}

func main() {

	var err error

	var bpfModule *bpf.Module
	var bpfMapEvents *bpf.BPFMap
	var bpfProgTcpConnect *bpf.BPFProg
	var perfBuffer *bpf.PerfBuffer

	var eventsChannel chan []byte
	var lostChannel chan uint64

	// create BPF module using BPF object file
	bpfModule, err = bpf.NewModuleFromFile("flowsnoop.bpf.o")
	if err != nil {
		errexit(err)
	}
	defer bpfModule.Close()

	// BPF map "events": resize it before object is loaded
	bpfMapEvents, err = bpfModule.GetMap("events")

	if err != nil {
		errexit(err)
	}
	err = bpfMapEvents.Resize(8192)

	// load BPF object from BPF module
	if err = bpfModule.BPFLoadObject(); err != nil {
		errexit(err)
	}

	// get config map
	bpfConfigMap, err := bpfModule.GetMap("config_map")
	if err != nil {
		errexit(err)
	}
	key := uint32(1)
	value := HexStringToNum(Pack32BinaryIP4("192.168.227.2"))
	err = bpfConfigMap.Update(unsafe.Pointer(&key), unsafe.Pointer(&value))
	if err != nil {
		errexit(err)
	}

	// get BPF program from BPF object
	bpfProgTcpConnect, err = bpfModule.GetProgram("tracepoint__net_netif_receive_skb")
	if err != nil {
		errexit(err)
	}

	// attach to BPF program to kprobe
	_, err = bpfProgTcpConnect.AttachTracepoint("net:netif_receive_skb")
	if err != nil {
		errexit(err)
	}

	// channel for events (and lost events)
	eventsChannel = make(chan []byte)
	lostChannel = make(chan uint64)

	perfBuffer, err = bpfModule.InitPerfBuf("events", eventsChannel, lostChannel, 1)
	if err != nil {
		errexit(err)
	}

	// start perf event polling (will receive events through eventChannel)
	perfBuffer.Start()

	fmt.Println("Listening for tcp_connect(), <Ctrl-C> or or SIG_TERM to end it.")

	timeout := make(chan bool)
	allgood := make(chan bool)

	go func() {
		time.Sleep(60 * time.Second) // this timeout is bigger than Makefile one
		timeout <- true
	}()

	go func() {
		// receive events until channel is closed
		for dataRaw := range eventsChannel {

			var dt data
			var dataBuffer *bytes.Buffer

			dataBuffer = bytes.NewBuffer(dataRaw)

			err = binary.Read(dataBuffer, binary.LittleEndian, &dt)
			if err != nil {
				fmt.Println("read data error: " + err.Error())
				continue
			}

			var bsport = make([]byte, 2)
			var bdport = make([]byte, 2)
			binary.BigEndian.PutUint16(bsport, dt.SPort)
			binary.BigEndian.PutUint16(bdport, dt.DPort)

			godata := gdata{
				Proto: uint(dt.Proto),
				SPort: uint(binary.LittleEndian.Uint16(bsport)),
				DPort: uint(binary.LittleEndian.Uint16(bdport)),
			}

			// TCPv4 only example

			var LeSAddr = make([]byte, 4)
			var LeDAddr = make([]byte, 4)

			binary.LittleEndian.PutUint32(LeSAddr, dt.SAddr)
			binary.LittleEndian.PutUint32(LeDAddr, dt.DAddr)
			godata.SAddr = net.IP.String(LeSAddr)
			godata.DAddr = net.IP.String(LeDAddr)

			fmt.Fprintf(os.Stdout, "(proto: %d) %s (%d) => %s (%d)\n",
				godata.Proto,
				godata.SAddr, godata.SPort,
				godata.DAddr, godata.DPort)

			if godata.DAddr == "127.0.0.1" {
				if godata.DPort == 12345 {
					// magic connection makes test succeed
					allgood <- true
				}
			}
		}
	}()

	select {
	case <-allgood:
		okexit()
	case <-timeout:
		errtimeout()
	}
}
