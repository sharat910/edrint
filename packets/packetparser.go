package packets

import (
	"net"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/eventbus"
	"github.com/spf13/viper"
)

type FiveTuple struct {
	SrcIP, DstIP     string
	SrcPort, DstPort uint16
	Protocol         uint8
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

func PacketParser(eventbus *eventbus.EventBus) {

	handle := GetHandle()
	dirMac := viper.GetString("packets.direction.mode") == "mac"
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
	if !dirMac {
		clientSubnets = GetClientSubnets()
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	packetSource.DecodeOptions.Lazy = true
	packetSource.DecodeOptions.NoCopy = true

	pktCount := 0
	log.Info().Msg("packet processor started")
	for packet := range packetSource.Packets() {
		pktCount++
		var p Packet
		p.Timestamp = packet.Metadata().Timestamp
		p.TotalLen = uint(packet.Metadata().Length)
		appLayer := packet.ApplicationLayer()
		if appLayer != nil {
			p.Payload = appLayer.LayerContents()
			//p.Payload = append(p.Payload, appLayer.Payload()...)
			if len(appLayer.Payload()) != 0 && len(appLayer.Payload()) != len(appLayer.LayerContents()) {
				log.Warn().
					Int("layer_content_len", len(appLayer.LayerContents())).
					Int("layer_payload_len", len(appLayer.Payload())).
					Msg("app layer len difference!")
			}
		}

		var foundLayerTypes []gopacket.LayerType
		_ = parser.DecodeLayers(packet.Data(), &foundLayerTypes)
		for _, layerType := range foundLayerTypes {
			switch layerType {
			case layers.LayerTypeEthernet:
				if dirMac {
					for _, clientMac := range viper.GetStringSlice("packets.direction.client_macs") {
						if ethLayer.SrcMAC.String() == clientMac {
							p.IsOutbound = true
							break
						}
					}
				}
			case layers.LayerTypeIPv4:
				p.Header.SrcIP = ip4Layer.SrcIP.String()
				p.Header.DstIP = ip4Layer.DstIP.String()
				p.Header.Protocol = uint8(ip4Layer.Protocol)
				if !dirMac {
					for _, s := range clientSubnets {
						if s.Contains(ip4Layer.SrcIP) {
							p.IsOutbound = true
							break
						}
					}
				}
			case layers.LayerTypeIPv6:
				p.Header.SrcIP = ip6Layer.SrcIP.String()
				p.Header.DstIP = ip6Layer.DstIP.String()
				p.Header.Protocol = uint8(ip6Layer.NextHeader)
				if !dirMac {
					for _, s := range clientSubnets {
						if s.Contains(ip6Layer.SrcIP) {
							p.IsOutbound = true
							break
						}
					}
				}
			case layers.LayerTypeICMPv4:
				eventbus.Publish("packet", p)
			case layers.LayerTypeUDP:
				p.Header.SrcPort = uint16(udpLayer.SrcPort)
				p.Header.DstPort = uint16(udpLayer.DstPort)
				eventbus.Publish("packet", p)
			case layers.LayerTypeTCP:
				p.Header.SrcPort = uint16(tcpLayer.SrcPort)
				p.Header.DstPort = uint16(tcpLayer.DstPort)
				p.TCPLayer = tcpLayer
				eventbus.Publish("packet", p)
			}
		}
	}
	log.Info().Int("packet_count", pktCount).Msg("packet processing completed")
}

func GetClientSubnets() []*net.IPNet {
	var clientSubnets []*net.IPNet
	for _, s := range viper.GetStringSlice("packets.direction.client_ips") {
		_, subnet, err := net.ParseCIDR(s)
		if err != nil {
			log.Fatal().Err(err).Str("subnet", s).Msg("unable to parse subnet")
		}
		clientSubnets = append(clientSubnets, subnet)
	}
	return clientSubnets
}

func GetHandle() *pcap.Handle {
	var handle *pcap.Handle
	source := viper.GetString("packets.source")
	if source == "pcap" {
		var err error
		pcapPath := viper.GetString("packets.pcap_path")
		handle, err = pcap.OpenOffline(pcapPath)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to open pcap")
		}
		log.Info().Str("packet_source", source).Str("pcap_path", pcapPath).Msg("handle created")
	} else if source == "interface" {
		var err error
		iface := viper.GetString("packets.interface")
		handle, err = pcap.OpenLive(iface, 9600, true, time.Minute)
		if err != nil {
			log.Fatal().Err(err).Msg("unable to open pcap")
		}
		log.Info().Str("packet_source", source).Str("interface", iface).Msg("handle created")
	}
	return handle
}
