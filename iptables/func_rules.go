package iptables

import (
	"bytes"
	"fmt"
	"sort"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jeremmfr/terraform-provider-iptables/internal/helper/hashcode"
)

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
		vs := v.(*schema.Set).List()
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
		lengthCIDRBlocks := len(ma["cidr_blocks"].(*schema.Set).List())

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
			for _, cidr := range ma["cidr_blocks"].(*schema.Set).List() {
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
	lengthCIDRBlocks := len(ma["cidr_blocks"].(*schema.Set).List())
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
		for _, cidr := range ma["cidr_blocks"].(*schema.Set).List() {
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

func checkRulesPositionAndCIDRList(d *schema.ResourceData) error {
	lenONCIDR := len(d.Get("on_cidr_blocks").(*schema.Set).List())
	for _, ingress := range d.Get("ingress").(*schema.Set).List() {
		ingressMap := ingress.(map[string]interface{})
		if ingressMap["position"].(string) != "?" {
			if lenONCIDR > one {
				return fmt.Errorf("position not possible with multiple 'on_cidr_blocks'")
			}
			if len(ingressMap["cidr_blocks"].(*schema.Set).List()) > one {
				return fmt.Errorf("position not possible with multiple 'cidr_blocks'")
			}
		}
	}
	for _, egress := range d.Get("egress").(*schema.Set).List() {
		egressMap := egress.(map[string]interface{})
		if egressMap["position"].(string) != "?" {
			if lenONCIDR > one {
				return fmt.Errorf("position not possible with multiple 'on_cidr_blocks'")
			}
			if len(egressMap["cidr_blocks"].(*schema.Set).List()) > one {
				return fmt.Errorf("position not possible with multiple 'cidr_blocks'")
			}
		}
	}

	return nil
}
