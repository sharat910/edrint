package processor

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
	"golang.org/x/crypto/cryptobyte"
	"golang.org/x/crypto/hkdf"
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

func bytesToInt16(byteSlice []byte) int {
	return int(byteSlice[0])<<8 + int(byteSlice[1])
}

func (dp *SNIParser) EventHandler(topic events.Topic, event interface{}) {
	p := event.(common.Packet)

	var sni string
	var present bool
	if p.Header.Protocol == 6 {
		sni, present = ExtractTCPSNI(p.Payload)
	} else if p.Header.Protocol == 17 && p.Header.DstPort == 443 {
		sni, present = ExtractQUICSNI(p)
	}

	if !present {
		return
	}
	dp.Publish(events.PROTOCOL_SNI, SNIRecord{
		Timestamp: p.Timestamp,
		SNI:       sni,
		Header:    p.GetKey(),
	})
	log.Debug().Str("sni", sni).Stringer("flow_tuple", p.Header).Msg("sni")
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

	if index+2 > pLen {
		return serverName, false
	}
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

type quicPacket struct {
	payload      []byte
	header       []byte
	packetNumber int64
}

func cleartextGquic(enc []byte, salt []byte) (decoded quicPacket, success bool) {
	// TODO properly parse the header for packetnumber and payload offset
	var payloadOffset int
	switch string(salt) {
	case "Q046":
		payloadOffset = 30
	default:
		payloadOffset = 26
	}
	return quicPacket{
		payload:      enc[payloadOffset:],
		header:       enc[:payloadOffset],
		packetNumber: 0,
	}, true
}

// With a UDP Payload, attempt to decrypt QUIC encrypction
func decodeQuic(enc []byte, salt []byte) (decoded quicPacket, success bool) {
	fb := enc[0]
	if !(fb&0xA0 == 0x80) {
		// Check if long header and initial/RTT
		log.Trace().Msg("long header init RTT")
		return
	}
	pktTypeInitial := fb&0x30 == 0x00

	dcidLen := int64(enc[5])
	dcid := enc[6 : 6+(dcidLen)]
	scidLen := int64(enc[6+dcidLen])

	idx := 6 + dcidLen + 1 + scidLen
	var tokenLengthLength, tokenLength int64
	if pktTypeInitial {
		tokenLengthLength, tokenLength = getVariableInt(enc[idx : idx+8])
		idx += tokenLengthLength + tokenLength
	}
	payloadLengthLength, payloadLength := getVariableInt(enc[idx : idx+8])
	totalLength := idx + payloadLengthLength + payloadLength
	if totalLength > int64(len(enc)) {
		log.Warn().Msg("len issue")
		return
	}

	pnOffset := 7 + dcidLen + scidLen + payloadLengthLength + tokenLengthLength + tokenLength
	sampleOffset := pnOffset + 4
	sample := enc[sampleOffset : sampleOffset+16]
	initialSecret := hkdf.Extract(sha256.New, dcid, salt)
	clientInitialSecret, _ := expandLabel(initialSecret, "client in", []byte(""), 32)
	hp, _ := expandLabel(clientInitialSecret, "quic hp", []byte(""), 16)
	mask := aesEncrypt(hp, sample)
	key, _ := expandLabel(clientInitialSecret, "quic key", []byte(""), 16)
	iv, _ := expandLabel(clientInitialSecret, "quic iv", []byte(""), 12)

	decodedHeader := make([]byte, 0)
	decodedHeader = append(decodedHeader, enc[0]^(mask[0]&0x0f))
	pnLength := int64(decodedHeader[0]&0x03 + 1)
	decodedHeader = append(decodedHeader, enc[1:pnOffset]...)
	decodedHeader = append(decodedHeader, xorBytes(enc[pnOffset:pnOffset+pnLength], mask[1:1+pnLength])...)

	pn := decodedHeader[pnOffset : pnOffset+pnLength]
	pn = append(make([]byte, len(iv)-len(pn)), pn...)
	nonce := xorBytes(iv, pn)

	decodedPayload, err := aeadDecrypt(key, nonce, enc[pnOffset+pnLength:pnOffset+pnLength+payloadLength-pnLength], decodedHeader)
	if err != nil {
		log.Trace().Err(err).Msg("aead error")
		return quicPacket{}, false
	}
	_, pnInt := getVariablePacketNumberInt(decodedHeader[pnOffset : pnOffset+pnLength])
	return quicPacket{
		payload:      decodedPayload,
		header:       decodedHeader,
		packetNumber: pnInt,
	}, true
}

func aeadDecrypt(key, nonce, ciphertext, associatedData []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	aesGCM, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	plaintext, err := aesGCM.Open(nil, nonce, ciphertext, associatedData)
	return plaintext, err
}

func expandLabel(secret []byte, label string, context []byte, length int) ([]byte, error) {
	var hkdfLabel cryptobyte.Builder
	hkdfLabel.AddUint16(uint16(length))
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes([]byte("tls13 "))
		b.AddBytes([]byte(label))
	})
	hkdfLabel.AddUint8LengthPrefixed(func(b *cryptobyte.Builder) {
		b.AddBytes(context)
	})
	out := make([]byte, length)
	n, err := hkdf.Expand(sha256.New, secret, hkdfLabel.BytesOrPanic()).Read(out)
	if err != nil || n != length {
		return nil, err
	}
	return out, nil
}

func getVariableInt(b []byte) (width, value int64) {
	if b == nil {
		log.Warn().Str("tag", "QUIC_SIGSEGV").Msg("b is nil in getVariableInt")
		return 0, 0
	}
	twoBit := b[0] >> 6
	switch twoBit {
	case 0:
		return 1, int64(b[0])
	case 1:
		return 2, int64(uint16(b[1]) | uint16(b[0]&0x3F)<<8)
	case 2:
		return 4, int64(uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0]&0x3F)<<24)
	case 3:
		return 8, int64(uint64(b[7]) | uint64(b[6])<<8 | uint64(b[5])<<16 | uint64(b[4])<<24 |
			uint64(b[3])<<32 | uint64(b[2])<<40 | uint64(b[1])<<48 | uint64(b[0]&0x3F)<<56)
	default:
		return 0, 0
	}
}

func getVariablePacketNumberInt(b []byte) (width, value int64) {
	if b == nil {
		log.Warn().Str("tag", "QUIC_SIGSEGV").Msg("b is nil in getVariablePacketNumberInt")
		return 0, 0
	}
	twoBit := b[0] >> 6
	switch twoBit {
	case 0, 1:
		return 1, int64(b[0])
	case 2:
		return 2, int64(uint16(b[1]) | uint16(b[0]&0x3F)<<8)
	case 3:
		return 4, int64(uint32(b[3]) | uint32(b[2])<<8 | uint32(b[1])<<16 | uint32(b[0]&0x3F)<<24)
	default:
		return 0, 0
	}
}

type ecb struct {
	b         cipher.Block
	blockSize int
}

func NewECB(b cipher.Block) *ecb {
	return &ecb{
		b:         b,
		blockSize: b.BlockSize(),
	}
}

type ecbEncrypter ecb

func newECBEncrypter(b cipher.Block) cipher.BlockMode {
	return (*ecbEncrypter)(NewECB(b))
}

func (x *ecbEncrypter) BlockSize() int {
	return x.blockSize
}

func (x *ecbEncrypter) CryptBlocks(dst, src []byte) {
	if len(src)%x.blockSize != 0 {
		panic("src needs to be a multiple of the block size.")
	}
	if len(dst) < len(src) {
		panic("dst cannot be smaller than src")
	}
	for len(src) > 0 {
		x.b.Encrypt(dst[:x.blockSize], src[:x.blockSize])
		src = src[x.blockSize:]
		dst = dst[x.blockSize:]
	}
}

func aesEncrypt(key, pt []byte) []byte {
	c, _ := aes.NewCipher(key)
	ecb := newECBEncrypter(c)
	ct := make([]byte, len(pt))
	ecb.CryptBlocks(ct, pt)
	return ct
}

func xorBytes(a, b []byte) (out []byte) {
	if len(a) != len(b) {
		panic("len a must equal b")
	}
	out = make([]byte, len(a))
	for i := range a {
		out[i] = a[i] ^ b[i]
	}
	return out
}

func tagsSni(payload []byte) (sni string, success bool) {
	if bytes.Compare(payload[4:8], []byte{0x43, 0x48, 0x4c, 0x4f}) == 0 {
		//Crypto
		var tags [][]byte
		var lengths []int
		var i int
		var sniOffset = -1
		var offset = 12
		for offset < len(payload) {
			tags = append(tags, payload[offset:offset+4])
			lengths = append(lengths, int(binary.LittleEndian.Uint16(payload[offset+4:offset+8])))
			if bytes.Compare(tags[i], []byte{0x53, 0x4e, 0x49, 0x00}) == 0 {
				sniOffset = i
			}
			if bytes.Compare(tags[i], []byte{0x53, 0x46, 0x43, 0x57}) == 0 {
				// sfcw is always the last tag?
				break
			}
			i++
			offset += 8
		}
		offset += 8
		if sniOffset == 0 {
			return string(payload[offset : offset+lengths[sniOffset]]), true
		} else if sniOffset > 0 {
			return string(payload[offset+lengths[sniOffset-1] : offset+lengths[sniOffset]]), true
		} else {
			return "", false
		}
	}
	return
}

func tlsSni(payload []byte) (sni string, success bool) {
	idx := 1
	cryptoOffsetWidth, cryptoOffset := getVariableInt(payload[idx : idx+4])
	if cryptoOffset != 0 {
		// offset should always be 0
		return
	}
	idx += int(cryptoOffsetWidth)
	cryptoLengthWidth, cryptoLength := getVariableInt(payload[idx : idx+4])
	idx += int(cryptoLengthWidth)
	pLen := len(payload)
	if cryptoLength > int64(pLen) {
		// Avoid out of bounds
		return
	}
	if payload[idx] != 0x01 {
		// Not a handshake packet, give up
		return
	}
	idx += 38
	sessionIdLen := int(payload[idx])
	idx += 1 + sessionIdLen // Skip over the session id
	if idx > pLen || sessionIdLen > 32 {
		// Session ID should be no more than 32
		return
	}
	cipherSuitesBytes := bytesToInt16(payload[idx : idx+2])
	idx += 2 + cipherSuitesBytes
	if idx > pLen {
		return
	}
	compressionMethodsLen := int(payload[idx])
	idx += 1 + compressionMethodsLen
	if idx > pLen {
		return
	}
	extensionsLength := int(uint16(payload[idx])<<8 | uint16(payload[idx+1]))
	idx += 2
	maxIdx := idx + extensionsLength
	if maxIdx > pLen {
		return
	}
	for idx < maxIdx {
		extensionCode := int(uint16(payload[idx])<<8 | uint16(payload[idx+1]))
		idx += 2
		extensionLength := int(uint16(payload[idx])<<8 | uint16(payload[idx+1]))
		idx += 2
		if extensionCode == 0 {
			idx += 2 // Skip over server name list length
			serverNameType := payload[idx]
			idx += 1
			if serverNameType == 0 {
				serverNameLength := int(uint16(payload[idx])<<8 | uint16(payload[idx+1]))
				idx += 2
				if idx+serverNameLength > pLen {
					return
				}
				sni = string(payload[idx : idx+serverNameLength])
				return sni, true
			}
		} else {
			idx += extensionLength
		}
	}
	return
}

func gquic051GetSni(packet quicPacket) (sni string, success bool) {
	payload := packet.payload
	frameType := payload[0]
	if frameType == 0x08 {
		return tlsSni(payload)
	}
	return
}

func genericGetQuicSni(packet quicPacket) (sni string, success bool) {
	if packet.packetNumber != 1 {
		//return "", false
	}
	payload := packet.payload
	frameType := payload[0]
	switch frameType {
	case 0x06:
		return tlsSni(payload)
	case 0x08:
		return tagsSni(payload)
	}
	return
}

func gquicOldGetSni(packet quicPacket) (sni string, success bool) {
	payload := packet.payload
	frameType := payload[0]
	if frameType != 0xa0 {
		return
	}
	idx := 4
	if !bytes.Equal(payload[idx:idx+4], []byte{0x43, 0x48, 0x4c, 0x4f}) {
		// Not CHLO
		return
	}
	numTags := int(binary.LittleEndian.Uint16(payload[idx+4 : idx+6]))
	// Jump ahead to the first tag after the CHLO
	idx += 8
	sniPresent := false
	sniStartOffset := uint32(0)
	sniEndOffset := uint32(0)
	prevOffset := uint32(0)
	for numTags > 0 {
		currentTag := binary.BigEndian.Uint32(payload[idx : idx+4])
		if currentTag == 0x534e4900 {
			// Hex for SNI tag keyword
			sniPresent = true
			sniStartOffset = prevOffset
			sniEndOffset = binary.LittleEndian.Uint32(payload[idx+4 : idx+8])
			idx += numTags * 8
			break
		} else if currentTag > 0x534e4900 {
			// No SNI tag will be found (the tags are ordered)
			break
		} else {
			// Some other tag
			prevOffset = binary.LittleEndian.Uint32(payload[idx+4 : idx+8])
			idx += 8
		}
		numTags -= 1
	}
	if !sniPresent {
		return
	}
	// idx is now at the start of the value section and the sni offsets have been set
	startIdx := idx + int(sniStartOffset)
	endIdx := idx + int(sniEndOffset)
	if startIdx > len(payload) {
		return
	}
	return string(payload[startIdx:endIdx]), true
}

type quicVersionDesc struct {
	salt      string
	decoder   func(enc []byte, salt []byte) (decoded quicPacket, success bool)
	extractor func(packet quicPacket) (sni string, success bool)
}

type quicVersion struct {
	version   []byte
	salt      []byte
	decoder   func(enc []byte, salt []byte) (decoded quicPacket, success bool)
	extractor func(packet quicPacket) (sni string, success bool)
}

var versionSalts = map[string]quicVersionDesc{
	"00000001": {salt: "38762cf7f55934b34d179ae6a4c80cadccbb7f0a"},
	"ff00001d": {salt: "afbfec289993d24c9e9786f19c6111e04390a899"},
	"faceb002": {salt: "c3eef712c72ebb5a11a7d2432bb46365bef9f502"},
	"ff00001b": {salt: "c3eef712c72ebb5a11a7d2432bb46365bef9f502"},
	"51303335": {decoder: cleartextGquic, extractor: gquicOldGetSni},                          // GQUIC Q035
	"51303433": {decoder: cleartextGquic, extractor: gquicOldGetSni},                          // GQUIC Q043
	"51303436": {decoder: cleartextGquic, extractor: gquicOldGetSni, salt: "51303436"},        // GQUIC Q046
	"51303530": {salt: "504574EFD066FE2F9D945CFCDBD3A7F0D3B56B45"},                            // GQUIC Q050
	"54303531": {salt: "7a4edef4e7ccee5fa4506c19124fc8ccda6e033d", extractor: gquic051GetSni}, // GQUIC Q051
}

var versionMap map[[4]byte]quicVersion

func init() {
	versionMap = make(map[[4]byte]quicVersion)
	for version, vDesc := range versionSalts {
		saltBytes, err := hex.DecodeString(vDesc.salt)
		if err != nil {
			log.Fatal().Msg("Error decoding string value of QUIC salt")
		}
		vb, err := hex.DecodeString(version)
		if err != nil {
			log.Fatal().Msg("Error decoding version of QUIC salt")
		}
		if len(vb) != 4 {
			log.Fatal().Msg("QUIC Version length != 4")
		}
		versionFixedBytes := [4]byte{
			vb[0],
			vb[1],
			vb[2],
			vb[3],
		}
		if vDesc.decoder == nil {
			vDesc.decoder = decodeQuic
		}
		if vDesc.extractor == nil {
			vDesc.extractor = genericGetQuicSni
		}
		versionMap[versionFixedBytes] = quicVersion{
			version:   vb,
			salt:      saltBytes,
			decoder:   vDesc.decoder,
			extractor: vDesc.extractor,
		}
	}
}

func getQuicVersion(enc []byte) (versionStruct quicVersion, success bool) {
	fb := enc[0]
	var version [4]byte
	switch {
	case fb&0xA0 == 0x80:
		// Long header/RTT
		version = [4]byte{enc[1], enc[2], enc[3], enc[4]}
	case enc[9] == 0x51:
		//fmt.Println("OLD GQUIC?", count)
		version = [4]byte{enc[9], enc[10], enc[11], enc[12]}
	default:
		//fmt.Println("NOT LONG HEADER", count)
		return
	}
	versionData, handledVersion := versionMap[version]
	if !handledVersion {
		return quicVersion{
			version:   nil,
			salt:      nil,
			decoder:   nil,
			extractor: nil,
		}, false
	}
	return versionData, true
}

func ExtractQUICSNI(p common.Packet) (string, bool) {
	version, handled := getQuicVersion(p.Payload)
	if !handled {
		return "", false
	}
	decodedPkt, decodedSuccess := version.decoder(p.Payload, version.salt)
	if !decodedSuccess {
		log.Trace().Str("version", fmt.Sprintf("%x", version.version)).
			Time("pt", p.Timestamp).Stringer("flow_tuple", p.Header).
			Msg("Unable to decode QUIC packet")
		return "", false
	}
	return version.extractor(decodedPkt)
}
