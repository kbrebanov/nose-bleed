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
        case *dns.CAA:
                rdata["flag"] = rr.Flag
                rdata["tag"] = rr.Tag
                rdata["value"] = rr.Value
        case *dns.CDNSKEY:
                rdata["flags"] = rr.Flags
                rdata["protocol"] = rr.Protocol
                rdata["algorithm"] = rr.Algorithm
                rdata["public_key"] = rr.PublicKey
        case *dns.CDS:
                rdata["key_tag"] = rr.KeyTag
                rdata["algorithm"] = rr.Algorithm
                rdata["digest_type"] = rr.DigestType
                rdata["digest"] = rr.Digest
        case *dns.CERT:
                rdata["type"] = dns.CertTypeToString[rr.Type]
                rdata["keytag"] = rr.KeyTag
                rdata["algorithm"] = dns.AlgorithmToString[rr.Algorithm]
                rdata["certificate"] = rr.Certificate
        case *dns.CNAME:
                rdata["target"] = rr.Target
        case *dns.DHCID:
                rdata["digest"] = rr.Digest
        case *dns.DLV:
                rdata["key_tag"] = rr.KeyTag
                rdata["algorithm"] = rr.Algorithm
                rdata["digest_type"] = rr.DigestType
                rdata["digest"] = rr.Digest
        case *dns.DNAME:
                rdata["target"] = rr.Target
        case *dns.DNSKEY:
                rdata["flags"] = rr.Flags
                rdata["protocol"] = rr.Protocol
                rdata["algorithm"] = rr.Algorithm
                rdata["public_key"] = rr.PublicKey
        case *dns.DS:
                rdata["key_tag"] = rr.KeyTag
                rdata["algorithm"] = rr.Algorithm
                rdata["digest_type"] = rr.DigestType
                rdata["digest"] = rr.Digest
        case *dns.EID:
                rdata["endpoint"] = rr.Endpoint
        case *dns.EUI48:
                rdata["address"] = rr.Address
        case *dns.EUI64:
                rdata["address"] = rr.Address
        case *dns.GID:
                rdata["gid"] = rr.Gid
        case *dns.GPOS:
                rdata["longitude"] = rr.Longitude
                rdata["latitude"] = rr.Latitude
                rdata["altitude"] = rr.Altitude
        case *dns.HINFO:
                rdata["cpu"] = rr.Cpu
                rdata["os"] = rr.Os
        case *dns.HIP:
                rdata["hit_length"] = rr.HitLength
                rdata["public_key_algorithm"] = rr.PublicKeyAlgorithm
                rdata["public_key_length"] = rr.PublicKeyLength
                rdata["hit"] = rr.Hit
                rdata["public_key"] = rr.PublicKey
                rdata["rendezvous_servers"] = rr.RendezvousServers
        case *dns.IPSECKEY:
                rdata["precedence"] = rr.Precedence
                rdata["gateway_type"] = rr.GatewayType
                rdata["algorithm"] = rr.Algorithm
                rdata["gateway_a"] = rr.GatewayA
                rdata["gateway_aaaa"] = rr.GatewayAAAA
                rdata["gateway_name"] = rr.GatewayName
                rdata["public_key"] = rr.PublicKey
        case *dns.KEY:
                rdata["flags"] = rr.Flags
                rdata["protocol"] = rr.Protocol
                rdata["algorithm"] = rr.Algorithm
                rdata["public_key"] = rr.PublicKey
        case *dns.KX:
                rdata["preference"] = rr.Preference
                rdata["exchanger"] = rr.Exchanger
        case *dns.L32:
                rdata["preference"] = rr.Preference
                rdata["locator32"] = rr.Locator32
        case *dns.L64:
                rdata["preference"] = rr.Preference
                rdata["locator64"] = rr.Locator64
        case *dns.LOC:
                rdata["version"] = rr.Version
                rdata["size"] = rr.Size
                rdata["horiz_pre"] = rr.HorizPre
                rdata["vert_pre"] = rr.VertPre
                rdata["latitude"] = rr.Latitude
                rdata["longitude"] = rr.Longitude
                rdata["altitude"] = rr.Altitude
        case *dns.LP:
                rdata["preference"] = rr.Preference
                rdata["fqdn"] = rr.Fqdn
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
        case *dns.NID:
                rdata["preference"] = rr.Preference
                rdata["node_id"] = rr.NodeID
        case *dns.NIMLOC:
                rdata["locator"] = rr.Locator
        case *dns.NINFO:
                rdata["zs_data"] = rr.ZSData
        case *dns.NS:
                rdata["ns"] = rr.Ns
        case *dns.NSAPPTR:
                rdata["ptr"] = rr.Ptr
        case *dns.NSEC:
                rdata["next_domain"] = rr.NextDomain
                rdata["type_bitmap"] = rr.TypeBitMap
        case *dns.NSEC3:
                rdata["hash"] = rr.Hash
                rdata["flags"] = rr.Flags
                rdata["iterations"] = rr.Iterations
                rdata["salt_length"] = rr.SaltLength
                rdata["salt"] = rr.Salt
                rdata["hash_length"] = rr.HashLength
                rdata["next_domain"] = rr.NextDomain
                rdata["type_bitmap"] = rr.TypeBitMap
        case *dns.NSEC3PARAM:
                rdata["hash"] = rr.Hash
                rdata["flags"] = rr.Flags
                rdata["iterations"] = rr.Iterations
                rdata["salt_length"] = rr.SaltLength
                rdata["salt"] = rr.Salt
        case *dns.OPENPGPKEY:
                rdata["public_key"] = rr.PublicKey
        case *dns.PTR:
                rdata["ptr"] = rr.Ptr
        case *dns.PX:
                rdata["preference"] = rr.Preference
                rdata["map822"] = rr.Map822
                rdata["mapx400"] = rr.Mapx400
        case *dns.RKEY:
                rdata["flags"] = rr.Flags
                rdata["protocol"] = rr.Protocol
                rdata["algorithm"] = rr.Algorithm
                rdata["public_key"] = rr.PublicKey
        case *dns.RP:
                rdata["mbox"] = rr.Mbox
                rdata["txt"] = rr.Txt
        case *dns.RRSIG:
                rdata["type_covered"] = rr.TypeCovered
                rdata["algorithm"] = rr.Algorithm
                rdata["labels"] = rr.Labels
                rdata["orig_ttl"] = rr.OrigTtl
                rdata["expiration"] = rr.Expiration
                rdata["inception"] = rr.Inception
                rdata["key_tag"] = rr.KeyTag
                rdata["signer_name"] = rr.SignerName
                rdata["signature"] = rr.Signature
        case *dns.RT:
                rdata["preference"] = rr.Preference
                rdata["host"] = rr.Host
        case *dns.SIG:
                rdata["type_covered"] = rr.TypeCovered
                rdata["algorithm"] = rr.Algorithm
                rdata["labels"] = rr.Labels
                rdata["orig_ttl"] = rr.OrigTtl
                rdata["expiration"] = rr.Expiration
                rdata["inception"] = rr.Inception
                rdata["key_tag"] = rr.KeyTag
                rdata["signer_name"] = rr.SignerName
                rdata["signature"] = rr.Signature
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
        case *dns.SSHFP:
                rdata["algorithm"] = rr.Algorithm
                rdata["type"] = rr.Type
                rdata["finger_print"] = rr.FingerPrint
        case *dns.TA:
                rdata["key_tag"] = rr.KeyTag
                rdata["algorithm"] = rr.Algorithm
                rdata["digest_type"] = rr.DigestType
                rdata["digest"] = rr.Digest
        case *dns.TALINK:
                rdata["previous_name"] = rr.PreviousName
                rdata["next_name"] = rr.NextName
        case *dns.TKEY:
                rdata["algorithm"] = rr.Algorithm
                rdata["inception"] = rr.Inception
                rdata["expiration"] = rr.Expiration
                rdata["mode"] = rr.Mode
                rdata["error"] = rr.Error
                rdata["key_size"] = rr.KeySize
                rdata["key"] = rr.Key
                rdata["other_len"] = rr.OtherLen
                rdata["other_data"] = rr.OtherData
        case *dns.TLSA:
                rdata["usage"] = rr.Usage
                rdata["selector"] = rr.Selector
                rdata["matching_type"] = rr.MatchingType
                rdata["certificate"] = rr.Certificate
        case *dns.TXT:
                rdata["txt"] = rr.Txt
        case *dns.UID:
                rdata["uid"] = rr.Uid
        case *dns.UINFO:
                rdata["uinfo"] = rr.Uinfo
        case *dns.URI:
                rdata["priority"] = rr.Priority
                rdata["weight"] = rr.Weight
                rdata["target"] = rr.Target
        case *dns.WKS:
                rdata["address"] = rr.Address
                rdata["protocol"] = rr.Protocol
                rdata["bitmap"] = rr.BitMap
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
