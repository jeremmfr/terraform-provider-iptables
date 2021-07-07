package iptables

import (
	"bytes"
	"fmt"
	"log"
	"net"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

const (
	numberElementsInIPRange = 2
	protocolIntICMPv6       = 58
	protocolIntUDP          = 17
	protocolIntTCP          = 6
	protocolIntICMP         = 1
)

func computeRemove(from []interface{}, to []interface{}) []interface{} {
	remove := make([]interface{}, 0)
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

	return remove
}

// protocolStateFunc ensures we only store a string in any protocol field.
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
// supports "tcp", "udp", "icmp", and "all".
func sgProtocolIntegers() map[string]int {
	protocolIntegers := map[string]int{
		"icmpv6": protocolIntICMPv6,
		"udp":    protocolIntUDP,
		"tcp":    protocolIntTCP,
		"icmp":   protocolIntICMP,
		"all":    -1,
	}

	return protocolIntegers
}

// ifaceStateFunc ensures we only store a string in any iface_* field.
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
	if len(ips) != numberElementsInIPRange {
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
			if len(ips) != numberElementsInIPRange {
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
			if len(ips) != numberElementsInIPRange {
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

func absolute(x int) int {
	if x < 0 {
		return -x
	}

	return x
}
