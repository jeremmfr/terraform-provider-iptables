package iptables

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"sort"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
)

func computeAddRemove(from []interface{}, to []interface{}) ([]interface{}, []interface{}) {
	add := make([]interface{}, 0)
	remove := make([]interface{}, 0)
	for _, u := range to {
		found := false
		for _, v := range from {
			if u == v {
				found = true
				break
			}
		}
		if !found {
			add = append(add, u)
		}
	}
	for _, u := range from {
		found := false
		for _, v := range to {
			if u == v {
				found = true
				break
			}
		}
		if !found {
			remove = append(remove, u)
		}
	}
	return add, remove
}

// protocolStateFunc ensures we only store a string in any protocol field
func protocolStateFunc(v interface{}) string {
	switch val := v.(type) {
	case string:
		p := protocolForValue(val)
		return p
	default:
		log.Printf("[WARN] Non String value given for Protocol: %#v", val)
		return ""
	}
}

// protocolForValue converts a valid Internet Protocol number into it's name
// representation. If a name is given, it validates that it's a proper protocol
// name. Names/numbers are as defined at
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml
func protocolForValue(v string) string {
	// special case -1
	protocol := strings.ToLower(v)
	if protocol == "-1" || protocol == strAll {
		return strAll
	}
	// if it's a name like tcp, return that
	if _, ok := sgProtocolIntegers()[protocol]; ok {
		return protocol
	}
	// convert to int, look for that value
	p, err := strconv.Atoi(protocol)
	if err != nil {
		// we were unable to convert to int, suggesting a string name, but it wasn't
		// found above
		log.Printf("[WARN] Unable to determine valid protocol: %s", err)
		return protocol
	}

	for k, v := range sgProtocolIntegers() {
		if p == v {
			// guard against protocolIntegers sometime in the future not having lower
			// case ids in the map
			return strings.ToLower(k)
		}
	}

	// fall through
	log.Printf("[WARN] Unable to determine valid protocol: no matching protocols found")
	return protocol
}

// a map of protocol names and their codes, defined at
// https://www.iana.org/assignments/protocol-numbers/protocol-numbers.xhtml,
// documented to be supported by AWS Security Groups
// http://docs.aws.amazon.com/fr_fr/AWSEC2/latest/APIReference/API_IpPermission.html
// Similar to protocolIntegers() used by Network ACLs, but explicitly only
// supports "tcp", "udp", "icmp", and "all"
func sgProtocolIntegers() map[string]int {
	protocolIntegers := map[string]int{
		"icmpv6": 58,
		"udp":    17,
		"tcp":    6,
		"icmp":   1,
		"all":    -1,
	}
	return protocolIntegers
}

// ifaceStateFunc ensures we only store a string in any iface_* field
func ifaceStateFunc(v interface{}) string {
	switch val := v.(type) {
	case string:
		iface := strings.ToLower(val)
		if iface == "-1" || iface == strAll || iface == "*" {
			return "*"
		}
		return iface
	default:
		log.Printf("[WARN] Non String value given for iface: %#v", val)
		return ""
	}
}

func computeOutSlicesOfMap(from []interface{}, to []interface{}) []interface{} {
	remove := make([]interface{}, 0)
	for _, u := range from {
		found := false
		mapFrom := u.(map[string]interface{})
		for _, v := range to {
			mapTo := v.(map[string]interface{})
			similar := true
			for keys := range mapFrom {
				if mapFrom[keys] != mapTo[keys] {
					similar = false
				}
			}
			if similar {
				found = true
				break
			}
		}
		if !found {
			remove = append(remove, u)
		}
	}
	return remove
}

func checkCIDRBlocksInMap(cidrSet map[string]interface{}, vers string) error {
	cidrExtract := cidrSet["cidr_blocks"].(string)
	var err error
	switch vers {
	case ipv4ver:
		if strings.Contains(cidrExtract, "-") {
			err = checkIPRange(cidrExtract)
		} else {
			err = checkCIDRNetworkOrHost(cidrExtract, ipv4ver)
		}
	case ipv6ver:
		if strings.Contains(cidrExtract, "-") {
			err = checkIPRange(cidrExtract)
		} else {
			err = checkCIDRNetworkOrHost(cidrExtract, ipv6ver)
		}
	}
	return err
}

func checkCIDRBlocksString(cidr string, vers string) error {
	var err error
	switch vers {
	case ipv4ver:
		if strings.Contains(cidr, "-") {
			err = checkIPRange(cidr)
		} else {
			err = checkCIDRNetworkOrHost(cidr, ipv4ver)
		}
	case ipv6ver:
		if strings.Contains(cidr, "-") {
			err = checkIPRange(cidr)
		} else {
			err = checkCIDRNetworkOrHost(cidr, ipv6ver)
		}
	}
	return err
}
func checkCIDRNetworkOrHost(nethost string, vers string) error {
	network := nethost
	if !strings.Contains(network, "/") {
		switch vers {
		case ipv4ver:
			network = strings.Join([]string{network, "/32"}, "")
		case ipv6ver:
			network = strings.Join([]string{network, "/128"}, "")
		default:
			return fmt.Errorf("checkCIDRNetworkOrHost call with unknown version")
		}
	}
	_, ipnet, err := net.ParseCIDR(network)
	if err != nil {
		return fmt.Errorf("%v is not a valid network CIDR or host", nethost)
	}
	if ipnet == nil || network != ipnet.String() {
		return fmt.Errorf("%v is not a valid network CIDR or host", nethost)
	}
	return nil
}
func checkIPRange(network string) error {
	ips := strings.Split(network, "-")
	if len(ips) != 2 {
		return fmt.Errorf("%v is not a valid IP range", network)
	}
	ip1 := net.ParseIP(ips[0])
	ip2 := net.ParseIP(ips[1])
	if ip1 == nil || ip2 == nil || bytes.Compare(ip1, ip2) > 0 {
		return fmt.Errorf("%v is not a valid IP range", network)
	}
	return nil
}

func validateCIDRNetworkOrHostV4() schema.SchemaValidateFunc {
	return func(i interface{}, k string) (s []string, es []error) {
		v := i.(string)
		if strings.Contains(v, "-") {
			ips := strings.Split(v, "-")
			if len(ips) != 2 {
				es = append(es, fmt.Errorf("%v is not a valid IP range", v))
			}
			ip1 := net.ParseIP(ips[0])
			ip2 := net.ParseIP(ips[1])
			if ip1 == nil || ip2 == nil || bytes.Compare(ip1, ip2) > 0 {
				es = append(es, fmt.Errorf("%v is not a valid IP range", v))
			}
		} else {
			network := v
			if !strings.Contains(v, "/") {
				network = strings.Join([]string{v, "/32"}, "")
			}
			_, ipnet, err := net.ParseCIDR(network)
			if err != nil {
				es = append(es, fmt.Errorf("%v is not a valid network CIDR or host", v))
			}
			if ipnet == nil || network != ipnet.String() {
				es = append(es, fmt.Errorf("%v is not a valid network CIDR or host", v))
			}
		}
		return
	}
}
func validateCIDRNetworkOrHostV6() schema.SchemaValidateFunc {
	return func(i interface{}, k string) (s []string, es []error) {
		v := i.(string)
		if strings.Contains(v, "-") {
			ips := strings.Split(v, "-")
			if len(ips) != 2 {
				es = append(es, fmt.Errorf("%v is not a valid IP range", v))
			}
			ip1 := net.ParseIP(ips[0])
			ip2 := net.ParseIP(ips[1])
			if ip1 == nil || ip2 == nil || bytes.Compare(ip1, ip2) > 0 {
				es = append(es, fmt.Errorf("%v is not a valid IP range", v))
			}
		} else {
			network := v
			if !strings.Contains(v, "/") {
				network = strings.Join([]string{v, "/128"}, "")
			}
			_, ipnet, err := net.ParseCIDR(network)
			if err != nil {
				es = append(es, fmt.Errorf("%v is not a valid network CIDR or host", v))
			}
			if ipnet == nil || network != ipnet.String() {
				es = append(es, fmt.Errorf("%v is not a valid network CIDR or host", v))
			}
		}
		return
	}
}
func ruleHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["from_port"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["to_port"].(string)))
	p := protocolForValue(m["protocol"].(string))
	buf.WriteString(fmt.Sprintf("%s-", p))
	buf.WriteString(fmt.Sprintf("%s-", m["iface_out"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["iface_in"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["state"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["icmptype"].(string)))
	buf.WriteString(fmt.Sprintf("%t-", m["fragment"].(bool)))
	buf.WriteString(fmt.Sprintf("%s-", m["action"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["position"].(string)))

	if v, ok := m["cidr_blocks"]; ok {
		vs := v.([]interface{})
		s := make([]string, len(vs))
		for i, raw := range vs {
			s[i] = raw.(string)
		}
		sort.Strings(s)
		for _, v := range s {
			buf.WriteString(fmt.Sprintf("%s-", v))
		}
	}
	return hashcode.String(buf.String())
}

func expandCIDRInGressList(gress []interface{}, version string) []interface{} {
	var newGress []interface{}

	for _, raw := range gress {
		ma := raw.(map[string]interface{})
		lengthCIDRBlocks := len(ma["cidr_blocks"].([]interface{}))

		if lengthCIDRBlocks == 0 {
			newCIDR := make(map[string]interface{})
			newCIDR["from_port"] = ma["from_port"].(string)
			newCIDR["to_port"] = ma["to_port"].(string)
			newCIDR["protocol"] = ma["protocol"].(string)
			newCIDR["iface_in"] = ma["iface_in"].(string)
			newCIDR["iface_out"] = ma["iface_out"].(string)
			newCIDR["action"] = ma["action"].(string)
			newCIDR["state"] = ma["state"].(string)
			newCIDR["icmptype"] = ma["icmptype"].(string)
			newCIDR["fragment"] = ma["fragment"].(bool)
			newCIDR["position"] = ma["position"].(string)
			switch version {
			case ipv4ver:
				newCIDR["cidr_blocks"] = ipv4All
			case ipv6ver:
				newCIDR["cidr_blocks"] = ipv6All
			}
			newGress = append(newGress, newCIDR)
		} else {
			for _, cidr := range ma["cidr_blocks"].([]interface{}) {
				newCIDR := make(map[string]interface{})
				newCIDR["from_port"] = ma["from_port"].(string)
				newCIDR["to_port"] = ma["to_port"].(string)
				newCIDR["protocol"] = ma["protocol"].(string)
				newCIDR["iface_in"] = ma["iface_in"].(string)
				newCIDR["iface_out"] = ma["iface_out"].(string)
				newCIDR["action"] = ma["action"].(string)
				newCIDR["state"] = ma["state"].(string)
				newCIDR["icmptype"] = ma["icmptype"].(string)
				newCIDR["fragment"] = ma["fragment"].(bool)
				newCIDR["position"] = ma["position"].(string)
				newCIDR["cidr_blocks"] = cidr.(string)
				newGress = append(newGress, newCIDR)
			}
		}
	}
	return newGress
}

func expandCIDRInGress(gress interface{}, version string) []interface{} {
	var returnGress []interface{}
	ma := gress.(map[string]interface{})
	lengthCIDRBlocks := len(ma["cidr_blocks"].([]interface{}))
	if lengthCIDRBlocks == 0 {
		newCIDR := make(map[string]interface{})
		newCIDR["from_port"] = ma["from_port"].(string)
		newCIDR["to_port"] = ma["to_port"].(string)
		newCIDR["protocol"] = ma["protocol"].(string)
		newCIDR["iface_in"] = ma["iface_in"].(string)
		newCIDR["iface_out"] = ma["iface_out"].(string)
		newCIDR["action"] = ma["action"].(string)
		newCIDR["state"] = ma["state"].(string)
		newCIDR["icmptype"] = ma["icmptype"].(string)
		newCIDR["fragment"] = ma["fragment"].(bool)
		newCIDR["position"] = ma["position"].(string)
		switch version {
		case ipv4ver:
			newCIDR["cidr_blocks"] = ipv4All
		case ipv6ver:
			newCIDR["cidr_blocks"] = ipv6All
		}
		returnGress = append(returnGress, newCIDR)
	} else {
		for _, cidr := range ma["cidr_blocks"].([]interface{}) {
			newCIDR := make(map[string]interface{})
			newCIDR["from_port"] = ma["from_port"].(string)
			newCIDR["to_port"] = ma["to_port"].(string)
			newCIDR["protocol"] = ma["protocol"].(string)
			newCIDR["iface_in"] = ma["iface_in"].(string)
			newCIDR["iface_out"] = ma["iface_out"].(string)
			newCIDR["action"] = ma["action"].(string)
			newCIDR["state"] = ma["state"].(string)
			newCIDR["icmptype"] = ma["icmptype"].(string)
			newCIDR["fragment"] = ma["fragment"].(bool)
			newCIDR["position"] = ma["position"].(string)
			newCIDR["cidr_blocks"] = cidr.(string)
			returnGress = append(returnGress, newCIDR)
		}
	}
	return returnGress
}

func expandCIDRInNatList(nat []interface{}, way string, version string) []interface{} {
	var newNat []interface{}

	for _, raw := range nat {
		ma := raw.(map[string]interface{})
		if ma["except_cidr_blocks"].(string) != "" {
			newCIDR := make(map[string]interface{})
			newCIDR["protocol"] = ma["protocol"].(string)
			newCIDR["iface"] = ma["iface"].(string)
			newCIDR["cidr_blocks"] = ma["except_cidr_blocks"].(string)
			newCIDR["position"] = ma["position"].(string)
			newCIDR["to_port"] = ma["to_port"].(string)
			newCIDR["nth_every"] = ma["nth_every"].(string)
			newCIDR["nth_packet"] = ma["nth_packet"].(string)
			newCIDR["except"] = true
			newCIDR["action"] = way
			switch version {
			case ipv4ver:
				newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
			case ipv6ver:
				newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
			}

			newNat = append(newNat, newCIDR)
		} else {
			lengthFilter := len(ma["filter_cidr_blocks"].([]interface{}))

			if lengthFilter == 0 {
				newCIDR := make(map[string]interface{})
				newCIDR["protocol"] = ma["protocol"].(string)
				newCIDR["iface"] = ma["iface"].(string)
				newCIDR["position"] = ma["position"].(string)
				newCIDR["to_port"] = ma["to_port"].(string)
				newCIDR["nth_every"] = ma["nth_every"].(string)
				newCIDR["nth_packet"] = ma["nth_packet"].(string)
				newCIDR["except"] = false
				newCIDR["action"] = way
				switch version {
				case ipv4ver:
					newCIDR["cidr_blocks"] = ipv4All
					newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
				case ipv6ver:
					newCIDR["cidr_blocks"] = ipv6All
					newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
				}

				newNat = append(newNat, newCIDR)
			} else {
				for _, cidr := range ma["filter_cidr_blocks"].([]interface{}) {
					newCIDR := make(map[string]interface{})
					newCIDR["protocol"] = ma["protocol"].(string)
					newCIDR["iface"] = ma["iface"].(string)
					newCIDR["cidr_blocks"] = cidr.(string)
					newCIDR["position"] = ma["position"].(string)
					newCIDR["to_port"] = ma["to_port"].(string)
					newCIDR["nth_every"] = ma["nth_every"].(string)
					newCIDR["nth_packet"] = ma["nth_packet"].(string)
					newCIDR["except"] = false
					newCIDR["action"] = way
					switch version {
					case ipv4ver:
						newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
					case ipv6ver:
						newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
					}
					newNat = append(newNat, newCIDR)
				}
			}
		}
	}
	return newNat
}

func expandCIDRInNat(nat interface{}, way string, version string) []interface{} {
	var returnNat []interface{}
	ma := nat.(map[string]interface{})
	if ma["except_cidr_blocks"].(string) != "" {
		newCIDR := make(map[string]interface{})
		newCIDR["protocol"] = ma["protocol"].(string)
		newCIDR["iface"] = ma["iface"].(string)
		newCIDR["cidr_blocks"] = ma["except_cidr_blocks"].(string)
		newCIDR["position"] = ma["position"].(string)
		newCIDR["to_port"] = ma["to_port"].(string)
		newCIDR["nth_every"] = ma["nth_every"].(string)
		newCIDR["nth_packet"] = ma["nth_packet"].(string)
		newCIDR["except"] = true
		newCIDR["action"] = way
		switch version {
		case ipv4ver:
			newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
		case ipv6ver:
			newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
		}
		returnNat = append(returnNat, newCIDR)
	} else {
		lengthFilter := len(ma["filter_cidr_blocks"].([]interface{}))

		if lengthFilter == 0 {
			newCIDR := make(map[string]interface{})
			newCIDR["protocol"] = ma["protocol"].(string)
			newCIDR["iface"] = ma["iface"].(string)
			newCIDR["position"] = ma["position"].(string)
			newCIDR["to_port"] = ma["to_port"].(string)
			newCIDR["nth_every"] = ma["nth_every"].(string)
			newCIDR["nth_packet"] = ma["nth_packet"].(string)
			newCIDR["except"] = false
			newCIDR["action"] = way
			switch version {
			case ipv4ver:
				newCIDR["cidr_blocks"] = ipv4All
				newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
			case ipv6ver:
				newCIDR["cidr_blocks"] = ipv6All
				newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
			}
			returnNat = append(returnNat, newCIDR)
		} else {
			for _, cidr := range ma["filter_cidr_blocks"].([]interface{}) {
				newCIDR := make(map[string]interface{})
				newCIDR["protocol"] = ma["protocol"].(string)
				newCIDR["iface"] = ma["iface"].(string)
				newCIDR["cidr_blocks"] = cidr.(string)
				newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
				newCIDR["position"] = ma["position"].(string)
				newCIDR["to_port"] = ma["to_port"].(string)
				newCIDR["nth_every"] = ma["nth_every"].(string)
				newCIDR["nth_packet"] = ma["nth_packet"].(string)
				newCIDR["except"] = false
				newCIDR["action"] = way
				switch version {
				case ipv4ver:
					newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/32", "", -1)
				case ipv6ver:
					newCIDR["nat_ip"] = strings.Replace(ma["nat_ip"].(string), "/128", "", -1)
				}
				returnNat = append(returnNat, newCIDR)
			}
		}
	}
	return returnNat
}

func checkNat(nat []interface{}) error {
	for _, raw := range nat {
		ma := raw.(map[string]interface{})
		lengthFilter := len(ma["filter_cidr_blocks"].([]interface{}))
		if (lengthFilter != 0) && (ma["except_cidr_blocks"].(string) != "") {
			return fmt.Errorf("conflict between filter_cidr_blocks and except_cidr_blocks")
		}
	}
	return nil
}

func absolute(x int) int {
	if x < 0 {
		return -x
	}
	return x
}
