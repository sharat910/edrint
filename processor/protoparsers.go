package processor

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type DNSParser struct {
	BasePublisher
}

func NewDNSParser() *DNSParser {
	return &DNSParser{}
}

type DNSRecord struct {
	Timestamp   time.Time
	Name        string
	DNSType     string
	CName       string
	ClientIP    string
	DNSServerIP string
	ServerIP    string
}

func (dp *DNSParser) Name() string {
	return "dns"
}

func (dp *DNSParser) Subs() []events.Topic {
	return []events.Topic{events.PACKET}
}

func (dp *DNSParser) Pubs() []events.Topic {
	return []events.Topic{events.PROTOCOL_DNS}
}

func (dp *DNSParser) EventHandler(topic events.Topic, event interface{}) {
	p := event.(common.Packet)

	// Packet Filter
	if p.Header.SrcPort != 53 || p.Header.Protocol != 17 {
		return
	}

	if len(p.Payload) == 0 {
		log.Warn().Str("header", fmt.Sprint(p.Header)).Uint("Len", p.TotalLen).Msg("dns 0 payload")
		return
	}

	var dns layers.DNS
	err := dns.DecodeFromBytes(p.Payload, gopacket.NilDecodeFeedback)
	if err != nil {
		fmt.Println(string(p.Payload))
		log.Fatal().Err(err).Msg("unable to parse DNS Payload")
	}

	for i := 0; i < int(dns.ANCount); i++ {
		dnsRec := dns.Answers[i]
		dr := DNSRecord{
			Timestamp:   p.Timestamp,
			Name:        string(dnsRec.Name),
			DNSType:     dnsRec.Type.String(),
			CName:       string(dnsRec.CNAME),
			ClientIP:    p.Header.DstIP,
			DNSServerIP: p.Header.SrcIP,
		}
		if dnsRec.Type == layers.DNSTypeA || dnsRec.Type == layers.DNSTypeAAAA {
			dr.ServerIP = dnsRec.IP.String()
			dp.Publish(events.PROTOCOL_DNS, dr)
		} else if dnsRec.Type == layers.DNSTypeCNAME {
			dr.ServerIP = ""
			dp.Publish(events.PROTOCOL_DNS, dr)
		}
	}
}

func (dp *DNSParser) Init() {
}

func (dp *DNSParser) Teardown() {
}

type SNIParser struct {
	BasePublisher
}

func NewSNIParser() *SNIParser {
	return &SNIParser{}
}

type SNIRecord struct {
	Timestamp time.Time
	SNI       string
	Header    common.FiveTuple
}

func (dp *SNIParser) Name() string {
	return "sni"
}

func (dp *SNIParser) Subs() []events.Topic {
	return []events.Topic{events.PACKET}
}

func (dp *SNIParser) Pubs() []events.Topic {
	return []events.Topic{events.PROTOCOL_SNI}
}

func ExtractTCPSNI(payload []byte) (string, bool) {
	pLen := len(payload)
	var serverName string
	// Check if the packet is a Client Hello
	if !(pLen > 6 && payload[0] == 0x16 && payload[5] == 0x01) {
		return serverName, false
	}
	sessionIdLength := int((payload[43:44])[0])
	// Start after <Session ID Length>
	index := 44

	// Skip over <Session IDs>
	index += sessionIdLength

	// Extract <Cipher Suite Length>
	cipherSuiteLength := bytesToInt16(payload[index : index+2])

	// Skip over <Cipher Suite Length>
	index += 2
	// Skip over <Cipher Suites>
	index += cipherSuiteLength

	if index >= pLen {
		return serverName, false
	}
	// Extract <Compression Methods Length>
	compressionMethodsLength := int(payload[index])
	// SKip over compression methods length field and compression lengths itself
	index += 1
	index += compressionMethodsLength

	// Extract <Extensions Length>
	extensionsLength := bytesToInt16(payload[index : index+2])
	// Skip over <Extensions Length>
	index += 2
	if index >= pLen {
		return serverName, false
	}
	for index < len(payload) {
		extensionCode := bytesToInt16(payload[index : index+2])
		index += 2
		if index >= pLen {
			return serverName, false
		}
		if extensionCode == 0 {
			serverNameLength := bytesToInt16(payload[index : index+2])
			serverNameLength -= 2
			index += 4
			if index >= pLen {
				return serverName, false
			}
			if int(payload[index]) == 0 {
				serverNameLength -= 3
				index += 3
				serverName = string(payload[index : index+serverNameLength])
				break
			}
		} else {
			extensionsLength = bytesToInt16(payload[index : index+2])
			index += 2
			index += extensionsLength
		}
	}
	return serverName, true
}

func bytesToInt16(byteSlice []byte) int {
	return int(byteSlice[0])<<8 + int(byteSlice[1])
}

func (dp *SNIParser) EventHandler(topic events.Topic, event interface{}) {
	p := event.(common.Packet)

	// Packet Filter
	if p.Header.Protocol != 6 {
		return
	}

	sni, present := ExtractTCPSNI(p.Payload)
	if !present {
		return
	}
	dp.Publish(events.PROTOCOL_SNI, SNIRecord{
		Timestamp: p.Timestamp,
		SNI:       sni,
		Header:    p.GetKey(),
	})
}
