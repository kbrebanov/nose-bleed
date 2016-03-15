package protocols

import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
        "github.com/miekg/dns"
)

type DNSHeader struct {
        ID int                        `json:"id"`
        Opcode string                 `json:"opcode"`
        Flags []string                `json:"flags"`
        Rcode string                  `json:"rcode"`
        TotalQuestions int            `json:"total_questions"`
        TotalAnswerRRS int            `json:"total_answer_rrs"`
        TotalAuthorityRRS int         `json:"total_authority_rrs"`
        TotalAdditionalRRS int        `json:"total_additional_rrs"`
        Questions []interface{}       `json:"questions"`
        AnswerRRS []interface{}       `json:"answer_rrs"`
        AuthorityRRS []interface{}    `json:"authority_rrs"`
        AdditionalRRS []interface{}   `json:"additional_rrs"`
}

type DNSQuestion struct {
        Name string                   `json:"name"`
        Qtype string                  `json:"type"`
        Qclass string                 `json:"class"`
}

type DNSRRHeader struct {
        Name string                   `json:"name"`
        Rrtype string                 `json:"type"`
        Class string                  `json:"class"`
        TTL int                       `json:"ttl"`
        Rdlength int                  `json:"rdata_length"`
        Rdata interface{}             `json:"rdata"`
}

func DNSRRParser(rr dns.RR) DNSRRHeader {
        rdata := make(map[string]interface{})

        switch rr := rr.(type) {
        case *dns.A:
                rdata["a"] = rr.A
        case *dns.AAAA:
                rdata["aaaa"] = rr.AAAA
        case *dns.AFSDB:
                rdata["subtype"] = rr.Subtype
                rdata["hostname"] = rr.Hostname
        //case *dns.CAA:
        //case *dns.CDNSKEY:
        //case *dns.CDS:
        case *dns.CERT:
                rdata["type"] = dns.CertTypeToString[rr.Type]
                rdata["keytag"] = rr.KeyTag
                rdata["algorithm"] = dns.AlgorithmToString[rr.Algorithm]
                rdata["certificate"] = rr.Certificate
        case *dns.CNAME:
                rdata["target"] = rr.Target
        //case *dns.DHCID:
        //case *dns.DLV:
        case *dns.DNAME:
                rdata["target"] = rr.Target
        //case *dns.DNSKEY:
        //case *dns.DS:
        //case *dns.EID:
        //case *dns.EUI48:
        //case *dns.EUI64:
        //case *dns.GID:
        case *dns.GPOS:
                rdata["longitude"] = rr.Longitude
                rdata["latitude"] = rr.Latitude
                rdata["altitude"] = rr.Altitude
        case *dns.HINFO:
                rdata["cpu"] = rr.Cpu
                rdata["os"] = rr.Os
        //case *dns.HIP:
        //case *dns.IPSECKEY:
        //case *dns.KEY:
        //case *dns.KX:
        //case *dns.L32:
        //case *dns.L64:
        //case *dns.LOC:
        //case *dns.LP:
        case *dns.MB:
                rdata["mb"] = rr.Mb
        case *dns.MD:
                rdata["md"] = rr.Md
        case *dns.MF:
                rdata["mf"] = rr.Mf
        case *dns.MG:
                rdata["mg"] = rr.Mg
        case *dns.MINFO:
                rdata["rmail"] = rr.Rmail
                rdata["email"] = rr.Email
        case *dns.MR:
                rdata["mr"] = rr.Mr
        case *dns.MX:
                rdata["preference"] = rr.Preference
                rdata["mx"] = rr.Mx
        case *dns.NAPTR:
                rdata["order"] = rr.Order
                rdata["preference"] = rr.Preference
                rdata["flags"] = rr.Flags
                rdata["service"] = rr.Service
                rdata["regexp"] = rr.Regexp
                rdata["replacement"] = rr.Replacement
        //case *dns.NID:
        //case *dns.NIMLOC:
        //case *dns.NINFO:
        case *dns.NS:
                rdata["ns"] = rr.Ns
        //case *dns.NSAPPTR:
        //case *dns.NSEC:
        //case *dns.NSEC3:
        //case *dns.NSEC3PARAM:
        //case *dns.OPENPGPKEY:
        case *dns.PTR:
                rdata["ptr"] = rr.Ptr
        case *dns.PX:
                rdata["preference"] = rr.Preference
                rdata["map822"] = rr.Map822
                rdata["mapx400"] = rr.Mapx400
        //case *dns.RKEY:
        case *dns.RP:
                rdata["mbox"] = rr.Mbox
                rdata["txt"] = rr.Txt
        //case *dns.RRSIG:
        case *dns.RT:
                rdata["preference"] = rr.Preference
                rdata["host"] = rr.Host
        //case *dns.SIG:
        case *dns.SOA:
                rdata["ns"] = rr.Ns
                rdata["mbox"] = rr.Mbox
                rdata["serial"] = rr.Serial
                rdata["refresh"] = rr.Refresh
                rdata["retry"] = rr.Retry
                rdata["expire"] = rr.Expire
                rdata["mininum_ttl"] = rr.Minttl
        case *dns.SPF:
                rdata["txt"] = rr.Txt
        case *dns.SRV:
                rdata["priority"] = rr.Priority
                rdata["weight"] = rr.Weight
                rdata["port"] = rr.Port
                rdata["target"] = rr.Target
        //case *dns.SSHFP:
        //case *dns.TA:
        //case *dns.TALINK:
        //case *dns.TKEY:
        //case *dns.TLSA:
        case *dns.TXT:
                rdata["txt"] = rr.Txt
        //case *dns.UID:
        //case *dns.UINFO:
        //case *dns.URI:
        //case *dns.WKS:
        case *dns.X25:
                rdata["psdn_address"] = rr.PSDNAddress
        }

        header := DNSRRHeader{
                Name: rr.Header().Name,
                Rrtype: dns.TypeToString[rr.Header().Rrtype],
                Class: dns.ClassToString[rr.Header().Class],
                TTL: int(rr.Header().Ttl),
                Rdlength: int(rr.Header().Rdlength),
                Rdata: rdata,
        }

        return header
}

func DNSParser(layer gopacket.Layer) DNSHeader {
        dnsFlags := make([]string, 0, 8)

        dnsLayer, _ := layer.(*layers.DNS)

        contents := dnsLayer.BaseLayer.LayerContents()

        dnsMsg := new(dns.Msg)
        dnsMsg.Unpack(contents)

        if ! dnsMsg.MsgHdr.Response {
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
                        Name: question.Name,
                        Qtype: dns.TypeToString[question.Qtype],
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
                ID: int(dnsMsg.MsgHdr.Id),
                Opcode: dns.OpcodeToString[dnsMsg.MsgHdr.Opcode],
                Flags: dnsFlags,
                Rcode: dns.RcodeToString[dnsMsg.MsgHdr.Rcode],
                TotalQuestions: dnsTotalQuestions,
                TotalAnswerRRS: dnsTotalAnswerRRS,
                TotalAuthorityRRS: dnsTotalAuthorityRRS,
                TotalAdditionalRRS: dnsTotalAdditionalRRS,
                Questions: dnsQuestions,
                AnswerRRS: dnsAnswerRRS,
                AuthorityRRS: dnsAuthorityRRS,
                AdditionalRRS: dnsAdditionalRRS,
        }

        return dnsHeader
}
