package iptables

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

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
				newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
			case ipv6ver:
				newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
			}

			newNat = append(newNat, newCIDR)
		} else {
			lengthFilter := len(ma["filter_cidr_blocks"].(*schema.Set).List())

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
					newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
				case ipv6ver:
					newCIDR["cidr_blocks"] = ipv6All
					newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
				}

				newNat = append(newNat, newCIDR)
			} else {
				for _, cidr := range ma["filter_cidr_blocks"].(*schema.Set).List() {
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
						newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
					case ipv6ver:
						newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
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
			newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
		case ipv6ver:
			newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
		}
		returnNat = append(returnNat, newCIDR)
	} else {
		lengthFilter := len(ma["filter_cidr_blocks"].(*schema.Set).List())

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
				newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
			case ipv6ver:
				newCIDR["cidr_blocks"] = ipv6All
				newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
			}
			returnNat = append(returnNat, newCIDR)
		} else {
			for _, cidr := range ma["filter_cidr_blocks"].(*schema.Set).List() {
				newCIDR := make(map[string]interface{})
				newCIDR["protocol"] = ma["protocol"].(string)
				newCIDR["iface"] = ma["iface"].(string)
				newCIDR["cidr_blocks"] = cidr.(string)
				newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
				newCIDR["position"] = ma["position"].(string)
				newCIDR["to_port"] = ma["to_port"].(string)
				newCIDR["nth_every"] = ma["nth_every"].(string)
				newCIDR["nth_packet"] = ma["nth_packet"].(string)
				newCIDR["except"] = false
				newCIDR["action"] = way
				switch version {
				case ipv4ver:
					newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/32", "")
				case ipv6ver:
					newCIDR["nat_ip"] = strings.ReplaceAll(ma["nat_ip"].(string), "/128", "")
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
		lengthFilter := len(ma["filter_cidr_blocks"].(*schema.Set).List())
		if (lengthFilter != 0) && (ma["except_cidr_blocks"].(string) != "") {
			return fmt.Errorf("conflict between filter_cidr_blocks and except_cidr_blocks")
		}
	}

	return nil
}

func checkNatPositionAndCIDRList(d *schema.ResourceData) error {
	lenONCIDR := len(d.Get("on_cidr_blocks").(*schema.Set).List())
	for _, snat := range d.Get("snat").(*schema.Set).List() {
		snatMap := snat.(map[string]interface{})
		if snatMap["position"].(string) != "?" {
			if lenONCIDR > one {
				return fmt.Errorf("position not possible with multiple 'on_cidr_blocks'")
			}
			if len(snatMap["filter_cidr_blocks"].(*schema.Set).List()) > one {
				return fmt.Errorf("position not possible with multiple 'filter_cidr_blocks'")
			}
		}
	}
	for _, dnat := range d.Get("dnat").(*schema.Set).List() {
		dnatMap := dnat.(map[string]interface{})
		if dnatMap["position"].(string) != "?" {
			if lenONCIDR > one {
				return fmt.Errorf("position not possible with multiple 'on_cidr_blocks'")
			}
			if len(dnatMap["filter_cidr_blocks"].(*schema.Set).List()) > one {
				return fmt.Errorf("position not possible with multiple 'filter_cidr_blocks'")
			}
		}
	}

	return nil
}
