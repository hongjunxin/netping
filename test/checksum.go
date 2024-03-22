package main

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"syscall"

	log "github.com/sirupsen/logrus"
	"golang.org/x/net/ipv4"
)

const (
	HDRLEN_IPV4 = 20
	HDRLEN_TCP  = 20
	HDRLEN_UDP  = 8
)

func init() {
	log.SetLevel(log.DebugLevel)
}

// other test: kernel will reset the ip header checksum in c++ test

func main() {
	src := net.IP([]byte{192, 168, 58, 4})
	dst := net.IP([]byte{192, 168, 58, 5})

	var b []byte
	var err error

	if b, err = marshalIPHeader(syscall.IPPROTO_TCP, src, dst); err != nil {
		log.Error("marshal ip header failed")
		os.Exit(1)
	}
	log.Infof("b len=%v, %v", len(b), b)

	var sum uint32 = 0
	for i := 0; i < len(b); i += 2 {
		sum += uint32(b[i])<<8 + uint32(b[i+1])
	}

	sum = sum>>16 + sum&0xffff
	log.Infof("sum=0x%x", sum)
	if sum == 0xffff {
		log.Info("test passed")
	} else {
		log.Info("test failed")
	}
}

func marshalIPHeader(nextProto int, src, dst net.IP) ([]byte, error) {
	h := ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      0,
		TTL:      255,
		Protocol: nextProto,
		Flags:    ipv4.DontFragment,
		Checksum: 0,
		Src:      src,
		Dst:      dst,
	}

	h.TotalLen = HDRLEN_IPV4 + 24
	if nextProto == syscall.IPPROTO_TCP {
		h.TotalLen += HDRLEN_TCP
	} else if nextProto == syscall.IPPROTO_UDP {
		h.TotalLen += HDRLEN_UDP
	} else {
		return nil, fmt.Errorf("proto id=%v not supported", nextProto)
	}

	var b []byte
	var err error
	b, err = h.Marshal()
	if err != nil {
		return nil, err
	}

	checksum := ipv4Checksum(b)
	binary.BigEndian.PutUint16(b[10:12], checksum)
	return b, nil
}

func ipv4Checksum(data []byte) uint16 {
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
