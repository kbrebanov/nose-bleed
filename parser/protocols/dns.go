package protocols

import (
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

type DNSHeader struct {
	ID                 int           `json:"id"`
	Opcode             string        `json:"opcode"`
	Flags              []string      `json:"flags"`
	Rcode              string        `json:"rcode"`
	TotalQuestions     int           `json:"total_questions"`
	TotalAnswerRRS     int           `json:"total_answer_rrs"`
	TotalAuthorityRRS  int           `json:"total_authority_rrs"`
	TotalAdditionalRRS int           `json:"total_additional_rrs"`
	Questions          []interface{} `json:"questions"`
	AnswerRRS          []interface{} `json:"answer_rrs"`
	AuthorityRRS       []interface{} `json:"authority_rrs"`
	AdditionalRRS      []interface{} `json:"additional_rrs"`
}

type DNSQuestion struct {
	Name   string `json:"name"`
	Qtype  string `json:"type"`
	Qclass string `json:"class"`
}

type DNSRRHeader struct {
	Name     string `json:"name"`
	Rrtype   string `json:"type"`
	Class    string `json:"class"`
	TTL      int    `json:"ttl"`
	Rdlength int    `json:"rdata_length"`
	Rdata    string `json:"rdata"`
}

// DNSRRParser parses DNS Resource Records
func DNSRRParser(rr dns.RR) DNSRRHeader {
	rrHeader := strings.Split(rr.String(), "\t")
	name := strings.TrimPrefix(rrHeader[0], ";")
	rrType := rrHeader[3]
	class := rrHeader[2]
	rdLength := int(rr.Header().Rdlength)

	ttl, err := strconv.Atoi(rrHeader[1])
	if err != nil {
		//handle error
	}

	rdata := strings.Join(rrHeader[4:], " ")

	header := DNSRRHeader{
		Name:     name,
		Rrtype:   rrType,
		Class:    class,
		TTL:      ttl,
		Rdlength: rdLength,
		Rdata:    rdata,
	}

	return header
}

// DNSParser parses a DNS header
func DNSParser(layer gopacket.Layer) DNSHeader {
	dnsFlags := make([]string, 0, 8)

	dnsLayer, _ := layer.(*layers.DNS)

	contents := dnsLayer.BaseLayer.LayerContents()

	dnsMsg := new(dns.Msg)
	dnsMsg.Unpack(contents)

	if !dnsMsg.MsgHdr.Response {
		dnsFlags = append(dnsFlags, "QR")
	}
	if dnsMsg.MsgHdr.Authoritative {
		dnsFlags = append(dnsFlags, "AA")
	}
	if dnsMsg.MsgHdr.Truncated {
		dnsFlags = append(dnsFlags, "TC")
	}
	if dnsMsg.MsgHdr.RecursionDesired {
		dnsFlags = append(dnsFlags, "RD")
	}
	if dnsMsg.MsgHdr.RecursionAvailable {
		dnsFlags = append(dnsFlags, "RA")
	}
	if dnsMsg.MsgHdr.Zero {
		dnsFlags = append(dnsFlags, "Z")
	}
	if dnsMsg.MsgHdr.AuthenticatedData {
		dnsFlags = append(dnsFlags, "AD")
	}
	if dnsMsg.MsgHdr.CheckingDisabled {
		dnsFlags = append(dnsFlags, "CD")
	}

	dnsTotalQuestions := len(dnsMsg.Question)
	dnsTotalAnswerRRS := len(dnsMsg.Answer)
	dnsTotalAuthorityRRS := len(dnsMsg.Ns)
	dnsTotalAdditionalRRS := len(dnsMsg.Extra)

	dnsQuestions := make([]interface{}, 0, dnsTotalQuestions)
	dnsAnswerRRS := make([]interface{}, 0, dnsTotalAnswerRRS)
	dnsAuthorityRRS := make([]interface{}, 0, dnsTotalAuthorityRRS)
	dnsAdditionalRRS := make([]interface{}, 0, dnsTotalAdditionalRRS)

	for _, question := range dnsMsg.Question {
		dnsQuestions = append(dnsQuestions, DNSQuestion{
			Name:   question.Name,
			Qtype:  dns.TypeToString[question.Qtype],
			Qclass: dns.ClassToString[question.Qclass],
		})
	}

	for _, answer := range dnsMsg.Answer {
		dnsAnswerRRS = append(dnsAnswerRRS, DNSRRParser(answer))
	}

	for _, authority := range dnsMsg.Ns {
		dnsAuthorityRRS = append(dnsAuthorityRRS, DNSRRParser(authority))
	}

	for _, additional := range dnsMsg.Extra {
		dnsAdditionalRRS = append(dnsAdditionalRRS, DNSRRParser(additional))
	}

	dnsHeader := DNSHeader{
		ID:                 int(dnsMsg.MsgHdr.Id),
		Opcode:             dns.OpcodeToString[dnsMsg.MsgHdr.Opcode],
		Flags:              dnsFlags,
		Rcode:              dns.RcodeToString[dnsMsg.MsgHdr.Rcode],
		TotalQuestions:     dnsTotalQuestions,
		TotalAnswerRRS:     dnsTotalAnswerRRS,
		TotalAuthorityRRS:  dnsTotalAuthorityRRS,
		TotalAdditionalRRS: dnsTotalAdditionalRRS,
		Questions:          dnsQuestions,
		AnswerRRS:          dnsAnswerRRS,
		AuthorityRRS:       dnsAuthorityRRS,
		AdditionalRRS:      dnsAdditionalRRS,
	}

	return dnsHeader
}
