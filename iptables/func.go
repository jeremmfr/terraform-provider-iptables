// Copyright 2017 Jeremy Muriel
//
// This file is part of terraform-provider-iptables.
//
// terraform-provider-iptables is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Foobar is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with terraform-provider-iptables.  If not, see <http://www.gnu.org/licenses/>.

package iptables

import (
    "log"
	"strings"
	"strconv"
)

func calcAddRemove(from []interface{}, to []interface{}) ([]interface{}, []interface{}) {
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
	switch v.(type) {
	case string:
		p := protocolForValue(v.(string))
		return p
	default:
		log.Printf("[WARN] Non String value given for Protocol: %#v", v)
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
	if protocol == "-1" || protocol == "all" {
		return "all"
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
	var protocolIntegers = make(map[string]int)
	protocolIntegers = map[string]int{
		"udp":  17,
		"tcp":  6,
		"icmp": 1,
		"all":  -1,
	}
	return protocolIntegers
}

// ifaceStateFunc ensures we only store a string in any iface_* field
func ifaceStateFunc(v interface{}) string {
	switch v.(type) {
	case string:
		iface := strings.ToLower(v.(string))
		if iface == "-1" || iface == "all" || iface == "*" {
			return "*"
		}
		return iface
	default:
		log.Printf("[WARN] Non String value given for iface: %#v", v)
		return ""
	}
}

func calcOutSlicesOfMap(from []interface{}, to []interface{}) []interface{} {
    remove := make([]interface{}, 0)
    for _, u := range from {
        found := false
        ma_from := u.(map[string]interface{})
		for _, v := range to {
			ma_to := v.(map[string]interface{})
			similar := true
			for keys := range ma_from {
				if ma_from[keys] != ma_to[keys] {
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
