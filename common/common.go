package common

import (
	"fmt"
	"time"

	"github.com/google/gopacket/layers"
)

type FiveTuple struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         uint8
}

func (ft FiveTuple) String() string {
	return fmt.Sprintf("%s:%d =%d= %s:%d", ft.SrcIP, ft.SrcPort, ft.Protocol, ft.DstIP, ft.DstPort)
}

type Packet struct {
	Timestamp  time.Time
	Header     FiveTuple
	TotalLen   uint
	Payload    []byte
	IsOutbound bool
	TCPLayer   layers.TCP
}

func (p Packet) GetKey() FiveTuple {
	if p.IsOutbound {
		return FiveTuple{
			SrcIP:    p.Header.DstIP,
			DstIP:    p.Header.SrcIP,
			SrcPort:  p.Header.DstPort,
			DstPort:  p.Header.SrcPort,
			Protocol: p.Header.Protocol,
		}
	} else {
		return p.Header
	}
}
