package protocols

import (
        "github.com/google/gopacket"
        "github.com/google/gopacket/layers"
        //"github.com/miekg/dns"
)

type DNSHeader struct {
        ID int                        `json:"id"`
        Flags []string                `json:"flags"`
        TotalQuestions int            `json:"total_questions"`
        TotalAnswerRRS int            `json:"total_answer_rrs"`
        TotalAuthorityRRS int         `json:"total_authority_rrs"`
        TotalAdditionalRRS int        `json:"total_additional_rrs"`
}

func DNSParser(layer gopacket.Layer) DNSHeader {
        dnsFlags := make([]string, 0, 8)

        dns, _ := layer.(*layers.DNS)

        //dnsFlags = append(dnsFlags, dns.OpCode.String())
        dnsFlags = append(dnsFlags, dns.ResponseCode.String())
        if dns.QR {
                dnsFlags = append(dnsFlags, "QR")
        }
        if dns.AA {
                dnsFlags = append(dnsFlags, "AA")
        }
        if dns.TC {
                dnsFlags = append(dnsFlags, "TC")
        }
        if dns.RD {
                dnsFlags = append(dnsFlags, "RD")
        }
        if dns.RA {
                dnsFlags = append(dnsFlags, "RA")
        }
        //if dns.Z {
        //        dnsFlags = append(dnsFlags, "Z")
        //}

        dnsHeader := DNSHeader {
                ID: int(dns.ID),
                Flags: dnsFlags,
                TotalQuestions: len(dns.Questions),
                TotalAnswerRRS: len(dns.Answers),
                TotalAuthorityRRS: len(dns.Authorities),
                TotalAdditionalRRS: len(dns.Additionals),
        }
        return dnsHeader
}
