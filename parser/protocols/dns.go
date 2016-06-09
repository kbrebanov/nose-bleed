package protocols

import (
	"strconv"
	"strings"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

// DNSHeader represents a DNS header
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

// DNSQuestion represents a DNS question
type DNSQuestion struct {
	Name   string `json:"name"`
	Qtype  string `json:"type"`
	Qclass string `json:"class"`
}

// DNSedns represents EDNS information
type DNSedns struct {
	Version int    `json:"edns_version"`
	Flags   string `json:"edns_flags"`
	UDPSize int    `json:"edns_udp_size"`
	NSID    string `json:"edns_nsid,omitempty"`
	Subnet  string `json:"edns_subnet,omitempty"`
	Cookie  string `json:"edns_cookie,omitempty"`
	UL      string `json:"edns_ul,omitempty"`
	LLQ     string `json:"edns_llq,omitempty"`
	DAU     string `json:"edns_dau,omitempty"`
	DHU     string `json:"edns_dhu,omitempty"`
	N3U     string `json:"edns_n3u,omitempty"`
	Local   string `json:"edns_local,omitempty"`
}

// DNSRRHeader represents a DNS Resource Record
type DNSRRHeader struct {
	Name     string `json:"name"`
	Rrtype   string `json:"type"`
	Class    string `json:"class"`
	TTL      int    `json:"ttl"`
	Rdlength int    `json:"rdata_length"`
	Rdata    string `json:"rdata"`
	*DNSedns `json:",omitempty"`
}

// DNSRRParser parses DNS Resource Records
func DNSRRParser(rr dns.RR) (DNSRRHeader, error) {
	var (
		rrHeader                   []string
		name, rrType, class, rdata string
		ttl, rdLength              int
		edns                       *DNSedns
	)

	// Setting the struct to nil ensures it won't be marshalled if it's empty
	edns = nil

	switch rr := rr.(type) {
	case *dns.OPT:
		edns = new(DNSedns)

		rrHeader = strings.Split(rr.Header().String(), "\t")

		// Get EDNS version
		edns.Version = int(rr.Version())

		// Get EDNS flags
		if rr.Do() {
			edns.Flags = "do"
		}

		// Get EDNS UDP Size
		edns.UDPSize = int(rr.UDPSize())

		// Get string representation of each option
		options := strings.Split(rr.String(), "\n")[2:]
		for _, opt := range options {
			opt = strings.TrimPrefix(opt, "; ")

			if strings.HasPrefix(opt, "NSID") {
				edns.NSID = strings.TrimPrefix(opt, "NSID: ")
			} else if strings.HasPrefix(opt, "SUBNET") {
				edns.Subnet = strings.TrimPrefix(opt, "SUBNET: ")
			} else if strings.HasPrefix(opt, "COOKIE") {
				edns.Cookie = strings.TrimPrefix(opt, "COOKIE: ")
			} else if strings.HasPrefix(opt, "UPDATE LEASE") {
				edns.UL = strings.TrimPrefix(opt, "UPDATE LEASE: ")
			} else if strings.HasPrefix(opt, "LONG LIVED QUERIES") {
				edns.LLQ = strings.TrimPrefix(opt, "LONG LIVED QUERIES: ")
			} else if strings.HasPrefix(opt, "DNSSEC ALGORITHM UNDERSTOOD") {
				edns.DAU = strings.TrimPrefix(opt, "DNSSEC ALGORITHM UNDERSTOOD: ")
			} else if strings.HasPrefix(opt, "DS HASH UNDERSTOOD") {
				edns.DHU = strings.TrimPrefix(opt, "DS HASH UNDERSTOOD: ")
			} else if strings.HasPrefix(opt, "NSEC3 HASH UNDERSTOOD") {
				edns.N3U = strings.TrimPrefix(opt, "NSEC3 HASH UNDERSTOOD: ")
			} else if strings.HasPrefix(opt, "LOCAL OPT") {
				edns.Local = strings.TrimPrefix(opt, "LOCAL OPT: ")
			}
		}
	// Any RR other than OPT
	default:
		// Get string representation of RR header and split it on tabs
		rrHeader = strings.Split(rr.String(), "\t")
	}

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
		DNSedns:  edns,
	}

	return header, nil
}

// DNSParser parses a DNS header
func DNSParser(layer gopacket.Layer) (DNSHeader, error) {
	dnsFlags := make([]string, 0, 8)

	dnsLayer := layer.(*layers.DNS)

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
		rr, err := DNSRRParser(answer)
		if err != nil {
			return DNSHeader{}, err
		}
		dnsAnswerRRS = append(dnsAnswerRRS, rr)
	}

	// Parse authority resource records
	for _, authority := range dnsMsg.Ns {
		rr, err := DNSRRParser(authority)
		if err != nil {
			return DNSHeader{}, err
		}
		dnsAuthorityRRS = append(dnsAuthorityRRS, rr)
	}

	// Parse additional resource records
	for _, additional := range dnsMsg.Extra {
		rr, err := DNSRRParser(additional)
		if err != nil {
			return DNSHeader{}, err
		}
		dnsAdditionalRRS = append(dnsAdditionalRRS, rr)
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
