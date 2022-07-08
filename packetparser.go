package edrint

import (
	"errors"
	"fmt"
	"net"
	"time"

	"github.com/sharat910/edrint/common"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/events"
)

type CaptureMode int

const (
	UNDEFINEDCM CaptureMode = iota
	PCAPFILE
	INTERFACE
)

type DirectionMode int

const (
	UNDEFINEDDM DirectionMode = iota
	CLIENT_MAC
	CLIENT_IP
)

type ParserConfig struct {
	CapMode    CaptureMode
	CapSource  string
	DirMode    DirectionMode
	DirMatches []string
	BPF        string
	MaxPackets int
}

func PacketParser(c ParserConfig, pf events.PubFunc) error {
	if err := SanityCheck(c); err != nil {
		return err
	}

	handle, err := GetHandle(c)
	if err != nil {
		return err
	}

	var (
		// Will reuse these for each packet
		ethLayer   layers.Ethernet
		ip4Layer   layers.IPv4
		ip6Layer   layers.IPv6
		icmp4Layer layers.ICMPv4
		tcpLayer   layers.TCP
		udpLayer   layers.UDP
	)

	parser := gopacket.NewDecodingLayerParser(
		layers.LayerTypeEthernet,
		&ethLayer,
		&ip4Layer,
		&ip6Layer,
		&icmp4Layer,
		&tcpLayer,
		&udpLayer,
	)

	// Uni IPs
	var clientSubnets []*net.IPNet
	if c.DirMode == CLIENT_IP {
		clientSubnets, err = GetClientSubnets(c)
		if err != nil {
			return err
		}
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	upPktCount := 0
	pktCount := 0
	log.Info().Msg("packet processor started")
	var firstPacketTS, lastPacketTS time.Time
	for packet := range packetSource.Packets() {
		pktCount++
		var p common.Packet
		p.Timestamp = packet.Metadata().Timestamp
		p.TotalLen = uint(packet.Metadata().Length)
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			p.Payload = appLayer.LayerContents()
			//p.Payload = append(p.Payload, appLayer.Payload()...)
			if len(appLayer.Payload()) != 0 && len(appLayer.Payload()) != len(appLayer.LayerContents()) {
				log.Trace().
					Int("layer_content_len", len(appLayer.LayerContents())).
					Int("layer_payload_len", len(appLayer.Payload())).
					Msg("app layer len difference!")
			}
		}
		// book keeping
		if pktCount == 1 {
			firstPacketTS = p.Timestamp
		}
		lastPacketTS = p.Timestamp
		var foundLayerTypes []gopacket.LayerType
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeEthernet:
				if c.DirMode == CLIENT_MAC {
					for _, clientMac := range c.DirMatches {
						if ethLayer.SrcMAC.String() == clientMac {
							p.IsOutbound = true
							upPktCount++
							break
						}
					}
				}
			case layers.LayerTypeIPv4:
				p.Header.SrcIP = ip4Layer.SrcIP.String()
				p.Header.DstIP = ip4Layer.DstIP.String()
				p.Header.Protocol = uint8(ip4Layer.Protocol)
				if c.DirMode == CLIENT_IP {
					for _, s := range clientSubnets {
						if s.Contains(ip4Layer.SrcIP) {
							p.IsOutbound = true
							upPktCount++
							break
						}
					}
				}
			case layers.LayerTypeIPv6:
				p.Header.SrcIP = ip6Layer.SrcIP.String()
				p.Header.DstIP = ip6Layer.DstIP.String()
				p.Header.Protocol = uint8(ip6Layer.NextHeader)
				if c.DirMode == CLIENT_IP {
					for _, s := range clientSubnets {
						if s.Contains(ip6Layer.SrcIP) {
							p.IsOutbound = true
							break
						}
					}
				}
			case layers.LayerTypeICMPv4:
				pf(events.PACKET, p)
			case layers.LayerTypeUDP:
				p.Header.SrcPort = uint16(udpLayer.SrcPort)
				p.Header.DstPort = uint16(udpLayer.DstPort)
				pf(events.PACKET, p)
			case layers.LayerTypeTCP:
				p.Header.SrcPort = uint16(tcpLayer.SrcPort)
				p.Header.DstPort = uint16(tcpLayer.DstPort)
				p.TCPLayer = tcpLayer
				pf(events.PACKET, p)
			}
		}
		if c.MaxPackets != 0 && pktCount >= c.MaxPackets {
			break
		}
	}
	log.Info().Int("packet_count", pktCount).Msg("packet processing completed")
	if upPktCount == 0 {
		log.Warn().Msg("No upload packet! Maybe check config.")
	}
	pf("packet_parser.metadata", struct {
		NPackets      int       `json:"n_packets"`
		UpPackets     int       `json:"up_packets"`
		FirstPacketTS time.Time `json:"first_packet_ts"`
		LastPacketTS  time.Time `json:"last_packet_ts"`
		Source        string
	}{pktCount, upPktCount, firstPacketTS, lastPacketTS, c.CapSource})
	return nil
}

func SanityCheck(c ParserConfig) error {
	if c.CapMode == UNDEFINEDCM {
		return errors.New("capture mode undefined")
	}

	if c.DirMode == UNDEFINEDDM {
		return errors.New("direction inference mode undefined")
	}
	return nil
}

func GetClientSubnets(c ParserConfig) ([]*net.IPNet, error) {
	var clientSubnets []*net.IPNet
	for _, s := range c.DirMatches {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			return clientSubnets, fmt.Errorf("unable to parse subnet: %s", s)
		}
		clientSubnets = append(clientSubnets, subnet)
	}
	return clientSubnets, nil
}

func GetHandle(c ParserConfig) (*pcap.Handle, error) {
	var err error
	var source string
	var handle *pcap.Handle
	switch c.CapMode {
	case PCAPFILE:
		handle, err = pcap.OpenOffline(c.CapSource)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to open pcap")
		}
		if c.BPF != "" {
			err = handle.SetBPFFilter(c.BPF)
			if err != nil {
				log.Fatal().Err(err).Msg("unable to set bpf filter")
			}
		}
		log.Info().Str("packet_source", source).Str("pcap_path", c.CapSource).Msg("handle created")
	case INTERFACE:
		handle, err = pcap.OpenLive(c.CapSource, 9600, true, time.Minute)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to open pcap")
		}
		log.Info().Str("packet_source", source).Str("interface", c.CapSource).Msg("handle created")
	default:
		return nil, errors.New("unknown capture mode")
	}
	return handle, nil
}
