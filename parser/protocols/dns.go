package protocols

import (
	"strconv"
	"strings"

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
func DNSRRParser(rr dns.RR) (DNSRRHeader, error) {
	var (
		name, rrType, class, rdata string
		ttl, rdLength              int
	)

	// Get string representation of RR header and split it on tabs
	rrHeader := strings.Split(rr.String(), "\t")

	// Extract respective fields from RR header
	headerLen := len(rrHeader)
	switch {
	case headerLen >= 1:
		name = strings.TrimPrefix(rrHeader[0], ";")
		fallthrough
	case headerLen >= 2:
		var err error

		ttl, err = strconv.Atoi(rrHeader[1])
		if err != nil {
			return DNSRRHeader{}, err
		}

		fallthrough
	case headerLen >= 3:
		class = rrHeader[2]
		fallthrough
	case headerLen >= 4:
		rrType = rrHeader[3]
		fallthrough
	case headerLen >= 5:
		rdata = strings.Join(rrHeader[4:], " ")
	}

	rdLength = int(rr.Header().Rdlength)

	header := DNSRRHeader{
		Name:     name,
		Rrtype:   rrType,
		Class:    class,
		TTL:      ttl,
		Rdlength: rdLength,
		Rdata:    rdata,
	}

	return header, nil
}

// DNSParser parses a DNS header
func DNSParser(dnsLayer layers.DNS) (DNSHeader, error) {
	dnsFlags := make([]string, 0, 8)

	contents := dnsLayer.BaseLayer.LayerContents()

	dnsMsg := new(dns.Msg)
	if err := dnsMsg.Unpack(contents); err != nil {
		return DNSHeader{}, err
	}

	// Parse flags
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

	// Parse questions
	for _, question := range dnsMsg.Question {
		dnsQuestions = append(dnsQuestions, DNSQuestion{
			Name:   question.Name,
			Qtype:  dns.TypeToString[question.Qtype],
			Qclass: dns.ClassToString[question.Qclass],
		})
	}

	// Parse answer resource records
	for _, answer := range dnsMsg.Answer {
		switch answer := answer.(type) {
		case *dns.OPT: // Skip OPT RRs
			continue
		default:
			rr, err := DNSRRParser(answer)
			if err != nil {
				return DNSHeader{}, err
			}
			dnsAnswerRRS = append(dnsAnswerRRS, rr)
		}
	}

	// Parse authority resource records
	for _, authority := range dnsMsg.Ns {
		switch authority := authority.(type) {
		case *dns.OPT: // Skip OPT RRs
			continue
		default:
			rr, err := DNSRRParser(authority)
			if err != nil {
				return DNSHeader{}, err
			}
			dnsAuthorityRRS = append(dnsAuthorityRRS, rr)
		}
	}

	// Parse additional resource records
	for _, additional := range dnsMsg.Extra {
		switch additional := additional.(type) {
		case *dns.OPT: // Skip OPT RRs
			continue
		default:
			rr, err := DNSRRParser(additional)
			if err != nil {
				return DNSHeader{}, err
			}
			dnsAdditionalRRS = append(dnsAdditionalRRS, rr)
		}
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

	return dnsHeader, nil
}
