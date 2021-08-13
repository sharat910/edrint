package processor

import (
	"fmt"
	"math"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/rs/zerolog/log"
	"github.com/sharat910/edrint/common"
	"github.com/sharat910/edrint/events"
)

type Rule struct {
	ClientSubnet    net.IPNet
	ServerSubnet    net.IPNet
	ClientPortRange [2]uint16
	ServerPortRange [2]uint16
	Protocol        uint8
	ProtocolMatch   bool
}

func GetStarRule() Rule {
	_, zeroSubnet, _ := net.ParseCIDR("0.0.0.0/0")
	return Rule{
		ClientSubnet:    *zeroSubnet,
		ServerSubnet:    *zeroSubnet,
		ClientPortRange: [2]uint16{0, math.MaxUint16},
		ServerPortRange: [2]uint16{0, math.MaxUint16},
	}
}

func BuildRule(config map[string]string) Rule {
	r := GetStarRule()

	protocol, exists := config["protocol"]
	if exists && protocol != "*" {
		protoInt, err := strconv.Atoi(protocol)
		if err != nil {
			log.Fatal().Err(err).Str("protocol", protocol).Msg("unable to parse rule")
		}
		r.Protocol = uint8(protoInt)
		r.ProtocolMatch = true
	}

	clientIP, exists := config["client_ip"]
	if exists && clientIP != "*" {
		fmt.Println(net.ParseCIDR(clientIP))
		_, subnet, err := net.ParseCIDR(clientIP)
		if err != nil {
			log.Fatal().Err(err).Str("client_ip_cidr", clientIP).Msg("unable to parse CIDR")
		}
		r.ClientSubnet = *subnet
	}

	serverIP, exists := config["server_ip"]
	if exists && serverIP != "*" {
		_, subnet, _ := net.ParseCIDR(serverIP)
		r.ServerSubnet = *subnet
	}

	clientPort, exists := config["client_port"]
	if exists && clientPort != "*" {
		clientPort = strings.Replace(clientPort, " ", "", -1)
		ports := strings.Split(clientPort, "-")
		var portInts []int
		for _, port := range ports {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal().Err(err).Str("client_port", clientPort).Msg("unable to parse rule")
			}
			portInts = append(portInts, portInt)
		}
		if len(portInts) == 1 {
			r.ClientPortRange[0] = uint16(portInts[0])
			r.ClientPortRange[1] = uint16(portInts[0])
		} else if len(portInts) == 2 {
			r.ClientPortRange[0] = uint16(portInts[0])
			r.ClientPortRange[1] = uint16(portInts[1])
		} else {
			log.Fatal().Ints("parsed_integer_ports", portInts).
				Str("client_port", clientPort).
				Msg("unable to parse rule")
		}
	}

	serverPort, exists := config["server_port"]
	if exists && serverPort != "*" {
		serverPort = strings.Replace(serverPort, " ", "", -1)
		ports := strings.Split(serverPort, "-")
		var portInts []int
		for _, port := range ports {
			portInt, err := strconv.Atoi(port)
			if err != nil {
				log.Fatal().Err(err).Str("server_port", serverPort).Msg("unable to parse rule")
			}
			portInts = append(portInts, portInt)
		}
		if len(portInts) == 1 {
			r.ServerPortRange[0] = uint16(portInts[0])
			r.ServerPortRange[1] = uint16(portInts[0])
		} else if len(portInts) == 2 {
			r.ServerPortRange[0] = uint16(portInts[0])
			r.ServerPortRange[1] = uint16(portInts[1])
		} else {
			log.Fatal().Ints("parsed_integer_ports", portInts).
				Str("server_port", serverPort).
				Msg("unable to parse rule")
		}
	}
	return r
}

func (r Rule) Match(header common.FiveTuple) bool {
	if r.ProtocolMatch && header.Protocol != r.Protocol {
		return false
	}

	if !(header.SrcPort >= r.ServerPortRange[0] && header.SrcPort <= r.ServerPortRange[1]) {
		return false
	}

	if !(header.DstPort >= r.ClientPortRange[0] && header.DstPort <= r.ClientPortRange[1]) {
		return false
	}

	serverIP := net.ParseIP(header.SrcIP)
	clientIP := net.ParseIP(header.DstIP)

	if !(r.ServerSubnet.Contains(serverIP) && r.ClientSubnet.Contains(clientIP)) {
		return false
	}
	return true
}

type HeaderClassifier struct {
	BasePublisher
	ruleConfig map[string]map[string]string
	Rules      map[string]Rule
}

func NewHeaderClassifer(ruleConfig map[string]map[string]string) *HeaderClassifier {
	hc := &HeaderClassifier{
		Rules: make(map[string]Rule),
	}
	for class, rule := range ruleConfig {
		hc.Rules[class] = BuildRule(rule)
	}
	return hc
}

func (hc *HeaderClassifier) Init() {
	log.Debug().Str("proc", hc.Name()).Str("rules", fmt.Sprint(hc.Rules)).Msg("init")
}

func (hc *HeaderClassifier) Name() string {
	return "header_classifier"
}

func (hc *HeaderClassifier) Subs() []events.Topic {
	return []events.Topic{events.FLOW_CREATED}
}

func (hc *HeaderClassifier) Pubs() []events.Topic {
	return []events.Topic{events.CLASSIFICATION}
}

func (hc *HeaderClassifier) EventHandler(topic events.Topic, event interface{}) {
	fc := event.(FlowCreatedEvent)
	for class, rule := range hc.Rules {
		if rule.Match(fc.Header) {
			log.Debug().Str("header", fmt.Sprint(fc.Header)).Str("class", class).Msg("classification")
			hc.Publish(events.CLASSIFICATION, EventClassification{
				Header: fc.Header,
				Class:  class,
			})
		}
	}
}

type EventClassification struct {
	Header common.FiveTuple
	Class  string
}

type SNIClassifier struct {
	BasePublisher
	rules map[string]*regexp.Regexp
}

func NewSNIClassifier(rules map[string]string) Processor {
	compiledRules := make(map[string]*regexp.Regexp)
	for class, reg := range rules {
		re, err := regexp.Compile(reg)
		if err != nil {
			log.Fatal().Str("regexp", reg).Err(err).Msg("regexp not compiling")
		}
		compiledRules[class] = re
	}
	return &SNIClassifier{rules: compiledRules}
}

func (S *SNIClassifier) Name() string {
	return "sni_classifier"
}

func (S *SNIClassifier) Subs() []events.Topic {
	return []events.Topic{events.PROTOCOL_SNI}
}

func (S *SNIClassifier) Pubs() []events.Topic {
	return []events.Topic{events.CLASSIFICATION}
}

func (S *SNIClassifier) EventHandler(topic events.Topic, event interface{}) {
	sni := event.(SNIRecord)
	for class, re := range S.rules {
		if re.MatchString(sni.SNI) {
			S.Publish(events.CLASSIFICATION, EventClassification{Header: sni.Header, Class: class})
		}
	}
}
