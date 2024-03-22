package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

type UserDataType int16

const (
	UDT_PING = UserDataType(10086) // todo: change to other value
)

const (
	FIN = 1  // 00 0001
	SYN = 2  // 00 0010
	RST = 4  // 00 0100
	PSH = 8  // 00 1000
	ACK = 16 // 01 0000
	URG = 32 // 10 0000
)

type TCPOption struct {
	Kind uint8
	Len  uint8
	Data []byte
}

type TCPHeader struct {
	Src        uint16
	Dst        uint16
	SeqNum     uint32
	AckNum     uint32
	DataOffset uint8 // 4 bits
	Reserved   uint8 // 3 bits
	ECN        uint8 // 3 bits
	Ctrl       uint8 // 6 bits
	Window     uint16
	Checksum   uint16
	Urgent     uint16
	Options    []TCPOption
}

type UDPHeader struct {
	Src      uint16
	Dst      uint16
	Len      uint16
	Checksum uint16
}

const (
	HDRLEN_IPV4 = 20
	HDRLEN_TCP  = 20
	HDRLEN_UDP  = 8
)

type UserData struct {
	Kind       int8
	_          int8 // binary.Read/Write() include padding
	Type       UserDataType
	Seq        int16
	DstSendCnt int16
	DstRecvCnt int16
	ProcTime   int32 // peer process time
	_          int8
	_          int8
	SendTs     int64
}

type TransportData struct {
	proto        int
	src, dst     []byte // ip
	sport, dport uint16
	ud           UserData
	udLen        int
}

type NetworkData struct {
	// todo: include ip header field
	td TransportData
}

// create tcp/udp packet include UserData
func createPacket(nd *NetworkData) ([]byte, error) {
	var ipHeader, transHeader, packet []byte
	var err error

	buf := &bytes.Buffer{}
	if err = binary.Write(buf, binary.BigEndian, &nd.td.ud); err != nil {
		log.Errorf("packet: binary.Write(UserData) failed, err=%v", err)
		return nil, err
	}
	nd.td.udLen = buf.Len() // don't use unsafe.Sizeof(UserData{})

	if ipHeader, err = marshalIPHeader(nd); err != nil {
		log.Errorf("packet: marshalIPHeader() failed, err=%v", err)
		return nil, err
	}
	if transHeader, err = marshalTransportHeader(&nd.td); err != nil {
		return nil, err
	}

	packet = append(packet, ipHeader...)
	packet = append(packet, transHeader...)
	packet = append(packet, buf.Bytes()...)
	return packet, nil
}

func marshalIPHeader(nd *NetworkData) ([]byte, error) {
	td := &nd.td
	h := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TTL:      255,
		Protocol: td.proto,
		Flags:    ipv4.DontFragment,
		Checksum: 0,
		Src:      td.src,
		Dst:      td.dst,
	}

	h.TotalLen = HDRLEN_IPV4 + td.udLen
	if td.proto == syscall.IPPROTO_TCP {
		h.TotalLen += HDRLEN_TCP
	} else if td.proto == syscall.IPPROTO_UDP {
		h.TotalLen += HDRLEN_UDP
	} else {
		return nil, fmt.Errorf("marshalIPHeader, proto id=%v not supported", td.proto)
	}

	var b []byte
	var err error
	b, err = h.Marshal()
	if err != nil {
		return nil, err
	}

	// kernel will fill checksum if we set to 0
	// but here we still do checksum
	ck := checksum(b)
	binary.BigEndian.PutUint16(b[10:12], ck)

	return b, nil
}

func checksum(data []byte) uint16 {
	var (
		sum    uint32
		length int = len(data)
		index  int
	)

	for length > 1 {
		sum += uint32(data[index])<<8 + uint32(data[index+1])
		index += 2
		length -= 2
	}
	if length > 0 {
		sum += uint32(data[index])
	}

	sum = (sum >> 16) + (sum & 0xffff)
	sum += (sum >> 16)

	return uint16(^sum)
}

func marshalTransportHeader(td *TransportData) ([]byte, error) {
	switch td.proto {
	case syscall.IPPROTO_UDP:
		dh := UDPHeader{
			Src:      td.sport,
			Dst:      td.dport,
			Len:      uint16(HDRLEN_UDP + td.udLen),
			Checksum: 0,
		}
		return dh.Marshal(), nil
	case syscall.IPPROTO_TCP:
		th := TCPHeader{
			Src:      td.sport,
			Dst:      td.dport,
			SeqNum:   0,
			AckNum:   1,
			Window:   65535,
			Checksum: 0, // let kernel calculate it
			Urgent:   1,
		}
		return th.Marshal(), nil
	default:
		return nil, fmt.Errorf("marshalTransportHeader, proto id=%v not supported", td.proto)
	}
}

func (tcp *TCPHeader) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, tcp.Src)
	binary.Write(buf, binary.BigEndian, tcp.Dst)
	binary.Write(buf, binary.BigEndian, tcp.SeqNum)
	binary.Write(buf, binary.BigEndian, tcp.AckNum)

	mix := uint16(tcp.DataOffset)<<12 | // top 4 bits
		uint16(tcp.Reserved)<<9 | // 3 bits
		uint16(tcp.ECN)<<6 | // 3 bits
		uint16(tcp.Ctrl) // bottom 6 bits
	binary.Write(buf, binary.BigEndian, mix)

	binary.Write(buf, binary.BigEndian, tcp.Window)
	binary.Write(buf, binary.BigEndian, tcp.Checksum)
	binary.Write(buf, binary.BigEndian, tcp.Urgent)

	for _, option := range tcp.Options {
		binary.Write(buf, binary.BigEndian, option.Kind)
		if option.Len > 1 {
			binary.Write(buf, binary.BigEndian, option.Len)
			binary.Write(buf, binary.BigEndian, option.Data)
		}
	}

	out := buf.Bytes()

	// Pad to min tcp header size, which is 20 bytes (5 32-bit words)
	pad := 20 - len(out)
	for i := 0; i < pad; i++ {
		out = append(out, 0)
	}

	return out
}

func (udp *UDPHeader) Marshal() []byte {
	buf := new(bytes.Buffer)
	binary.Write(buf, binary.BigEndian, udp.Src)
	binary.Write(buf, binary.BigEndian, udp.Dst)
	binary.Write(buf, binary.BigEndian, udp.Len)
	binary.Write(buf, binary.BigEndian, udp.Checksum)

	return buf.Bytes()
}
