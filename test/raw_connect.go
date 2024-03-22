package main

import (
	"net"
	"testing"
	"time"

	"golang.org/x/net/ipv4"
)

func main() {
}

func writeThenReadDatagram(t *testing.T, i int, c *ipv4.RawConn, wb []byte, src, dst net.Addr) []byte {
	rb := make([]byte, ipv4.HeaderLen+len(wb))
	wh := &ipv4.Header{
		Version:  ipv4.Version,
		Len:      ipv4.HeaderLen,
		TOS:      i + 1,
		TotalLen: ipv4.HeaderLen + len(wb),
		TTL:      i + 1,
		Protocol: 1,
	}
	if src != nil {
		wh.Src = src.(*net.IPAddr).IP
	}
	if dst != nil {
		wh.Dst = dst.(*net.IPAddr).IP
	}
	c.SetDeadline(time.Now().Add(100 * time.Millisecond))
	if err := c.WriteTo(wh, wb, nil); err != nil {
		t.Fatalf("ipv4.RawConn.WriteTo failed: %v", err)
	}
	rh, b, cm, err := c.ReadFrom(rb)
	if err != nil {
		t.Fatalf("ipv4.RawConn.ReadFrom failed: %v", err)
	}
	t.Logf("rcvd cmsg: %v", cm.String())
	t.Logf("rcvd hdr: %v", rh.String())
	return b
}
