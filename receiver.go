package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"syscall"
	"time"

	"github.com/AkihiroSuda/go-netfilter-queue"
	"github.com/google/gopacket/layers"
	log "github.com/sirupsen/logrus"
)

type RecvType int

const (
	RECV_TYPE_BEGIN = RecvType(0)
	RECV_PING       = RECV_TYPE_BEGIN
	RECV_ACK        = RecvType(1)
	RECV_TYPE_END   = RECV_ACK
)

type Receiver struct {
	nfq     *netfilter.NFQueue
	socket  int
	rcvType RecvType
}

type AppData struct {
	ud     UserData
	recvTs int64
}

func (r *Receiver) init(t RecvType) error {
	if t < RECV_TYPE_BEGIN || t > RECV_TYPE_END {
		return errors.New("RecvType out of range")
	}
	r.rcvType = t
	var err error
	if r.nfq, err = netfilter.NewNFQueue(QUEUE_NUM_RECEIVER,
		1024*10, netfilter.NF_DEFAULT_PACKET_SIZE); err != nil {
		return err
	}

	if r.rcvType == RECV_PING {
		if r.socket, err = syscall.Socket(syscall.AF_INET, syscall.SOCK_RAW,
			syscall.IPPROTO_TCP|syscall.IPPROTO_UDP); err != nil {
			return err
		}
		if err = syscall.SetsockoptInt(r.socket, syscall.IPPROTO_IP,
			syscall.IP_HDRINCL, 1); err != nil {
			return err
		}
		// todo: lack SO_TIMESTAMP ?
	}

	return nil
}

// hostA:ping() --> hostB:recv(RECV_PING)
//
// --> hostB:sendAck() --> hostA:recv(RECV_ACK)
func (r *Receiver) recv() {
	go func() {
		log.Debug("recv: goroutine run")
		defer r.nfq.Close()
		packets := r.nfq.GetPackets()
		for {
			select {
			case p := <-packets:
				// todo: not got udp packet from libnetfilter, bug ?
				switch p.Packet.TransportLayer().LayerType() {
				case layers.LayerTypeUDP:
				case layers.LayerTypeTCP:
					log.Debugf("netfilter got packet, p=%v", p.Packet)
					go r.handlePacket(&p)
				default:
					p.SetRequeueVerdict(uint16(netfilter.NF_ACCEPT))
				}
			case q := <-recvQuit:
				if q {
					log.Debug("recv: goroutine quit")
					return
				}
			case <-time.After(20 * time.Millisecond):
				// todo: do some cleanup
			}
		}
	}()
}

func (r *Receiver) handlePacket(p *netfilter.NFPacket) {
	appLayer := p.Packet.ApplicationLayer()
	log.Debugf("applayer Payload size=%v", len(appLayer.Payload()))
	ad := &AppData{}
	ad.recvTs = time.Now().Unix()
	ud := &ad.ud
	buf := bytes.NewBuffer(appLayer.Payload())
	if err := binary.Read(buf, binary.BigEndian, ud); err != nil {
		log.Errorf("receiver: binary.Read(appPayload) failed, err=%v", err)
		return
	}

	switch ud.Type {
	case UDT_PING:
		if r.rcvType == RECV_ACK {
			r.statAck(p)
		} else if r.rcvType == RECV_PING {
			r.sendAck(p, ad)
		} else {
			p.SetRequeueVerdict(uint16(netfilter.NF_ACCEPT))
			break
		}
		p.SetRequeueVerdict(uint16(netfilter.NF_DROP))
	default:
		p.SetRequeueVerdict(uint16(netfilter.NF_ACCEPT))
	}
}

func (r *Receiver) sendAck(p *netfilter.NFPacket, ad *AppData) {
	nd := &NetworkData{}
	td := &nd.td
	ud := &ad.ud

	// exchage srcIP/dstIP sport/dport
	netLayer := p.Packet.NetworkLayer()
	transLayer := p.Packet.TransportLayer()
	td.src = netLayer.NetworkFlow().Dst().Raw()
	td.dst = netLayer.NetworkFlow().Src().Raw()
	s := transLayer.TransportFlow().Src().Raw()
	d := transLayer.TransportFlow().Dst().Raw()
	td.sport = uint16(d[0])<<8 + uint16(d[1])
	td.dport = uint16(s[0])<<8 + uint16(s[1])

	if transLayer.LayerType() == layers.LayerTypeTCP {
		td.proto = syscall.IPPROTO_TCP
	} else {
		td.proto = syscall.IPPROTO_UDP
	}

	td.ud.Type = ud.Type
	td.ud.SendTs = time.Now().Unix()
	td.ud.ProcTime = int32(td.ud.SendTs - ad.recvTs)

	// todo: how to handle
	td.ud.DstRecvCnt++
	td.ud.DstSendCnt++

	log.Debugf("sendAck %v:%v => %v:%v, proto=%v, ud.Type=%v",
		td.src, td.sport, td.dst, td.dport, td.proto, ud.Type)
	log.Debugf("sendAck recv.DstSendCnt=%v, recv.DstRecvCnt=%v", ud.DstSendCnt, ud.DstRecvCnt)
	log.Debugf("sendAck ack.DstSendCnt=%v, ack.DstRecvCnt=%v, ack.ProcTime=%v, ack.SendTs=%v",
		td.ud.DstSendCnt, td.ud.DstRecvCnt, td.ud.ProcTime, td.ud.SendTs)

	var packet []byte
	var err error
	if packet, err = createPacket(nd); err != nil {
		log.Errorf("sendAck: createPacket() failed, err=%v", err)
		return
	}

	addr := syscall.SockaddrInet4{}
	addr.Port = int(td.dport)
	copy(addr.Addr[:], td.dst)
	// todo: socket fd concurrent write?
	err = syscall.Sendto(r.socket, packet, 0, &addr)
	if err != nil {
		log.Errorf("sendAck: Sendto() failed, err=%v", err)
	}
}

func (r *Receiver) statAck(p *netfilter.NFPacket) {

}
