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
}

func DNSParser(layer gopacket.Layer) DNSHeader {
        dnsFlags := make([]string, 0, 8)

        dnsLayer, _ := layer.(*layers.DNS)

        contents := dnsLayer.BaseLayer.LayerContents()
        //payload := dnsLayer.BaseLayer.LayerPayload()

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

        dnsHeader := DNSHeader {
                ID: int(dnsMsg.MsgHdr.Id),
                Opcode: dns.OpcodeToString[dnsMsg.MsgHdr.Opcode],
                Flags: dnsFlags,
                Rcode: dns.RcodeToString[dnsMsg.MsgHdr.Rcode],
                TotalQuestions: dnsTotalQuestions,
                TotalAnswerRRS: dnsTotalAnswerRRS,
                TotalAuthorityRRS: dnsTotalAuthorityRRS,
                TotalAdditionalRRS: dnsTotalAdditionalRRS,
        }
        return dnsHeader
}
