package iptables

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/jeremmfr/terraform-provider-iptables/internal/helper/hashcode"
)

const (
	strDnat string = "dnat"
	strSnat string = "snat"
)

func resourceNat() *schema.Resource {
	return &schema.Resource{
		Create: resourceNatCreate,
		Read:   resourceNatRead,
		Update: resourceNatUpdate,
		Delete: resourceNatDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"on_cidr_blocks": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"snat": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"to_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"protocol": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: protocolStateFunc,
							Default:   "all",
						},
						"iface": {
							Type:      schema.TypeString,
							Required:  true,
							StateFunc: ifaceStateFunc,
						},
						"filter_cidr_blocks": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"except_cidr_blocks": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateCIDRNetworkOrHostV4(),
						},
						"nat_ip": {
							Type:     schema.TypeString,
							Required: true,
						},
						"nth_every": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"nth_packet": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"position": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "?",
						},
					},
				},
				Set: natHash,
			},
			"dnat": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"to_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"protocol": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: protocolStateFunc,
							Default:   "all",
						},
						"iface": {
							Type:      schema.TypeString,
							Required:  true,
							StateFunc: ifaceStateFunc,
						},
						"filter_cidr_blocks": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"except_cidr_blocks": {
							Type:         schema.TypeString,
							Optional:     true,
							ValidateFunc: validateCIDRNetworkOrHostV4(),
						},
						"nat_ip": {
							Type:     schema.TypeString,
							Required: true,
						},
						"nth_every": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"nth_packet": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"position": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "?",
						},
					},
				},
				Set: natHash,
			},
		},
	}
}

func resourceNatCreate(d *schema.ResourceData, m interface{}) error {
	if err := resourceNatUpdate(d, m); err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceNatRead(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, _ := d.GetChange("on_cidr_blocks")
		err := natReadOnCIDR(oldOnCIDR.(*schema.Set).List(), d, m)
		if err != nil {
			return err
		}
	} else {
		err := natReadOnCIDR(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			return err
		}
	}
	if (len(d.Get("snat").(*schema.Set).List()) == 0) && (len(d.Get("dnat").(*schema.Set).List()) == 0) {
		d.SetId("")
	}

	return nil
}

func resourceNatUpdate(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}

	err := checkNatPositionAndCIDRList(d)
	if err != nil {
		d.SetId("")

		return err
	}
	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, newOnCIDR := d.GetChange("on_cidr_blocks")
		onCIDRRemove := computeRemove(oldOnCIDR.(*schema.Set).List(), newOnCIDR.(*schema.Set).List())
		err = natRemoveOnCIDR(onCIDRRemove, d, m)
		if err != nil {
			d.SetId("")

			return err
		}
		err = natAddOnCIDR(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return err
		}
	} else {
		err = natAddOnCIDR(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return err
		}
	}
	client := m.(*Client)
	err = client.saveV4()
	if err != nil {
		return fmt.Errorf("iptables save failed : %s", err)
	}

	return nil
}

func resourceNatDelete(d *schema.ResourceData, m interface{}) error {
	err := natRemoveOnCIDR(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
	if err != nil {
		d.SetId(d.Get("name").(string) + "!")

		return err
	}
	client := m.(*Client)
	err = client.saveV4()
	if err != nil {
		return fmt.Errorf("iptables save failed : %s", err)
	}

	return nil
}

func natHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["to_port"].(string)))
	p := protocolForValue(m["protocol"].(string))
	buf.WriteString(fmt.Sprintf("%s-", p))
	buf.WriteString(fmt.Sprintf("%s-", strings.ReplaceAll(m["nat_ip"].(string), "/32", "")))
	buf.WriteString(fmt.Sprintf("%s-", m["iface"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["position"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["nth_every"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["nth_packet"].(string)))

	if v, ok := m["filter_cidr_blocks"]; ok {
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

func natReadOnCIDR(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("snat") {
			oldSnat, _ := d.GetChange("snat")
			err := natListCommand(cidr.(string), oldSnat.(*schema.Set).List(), strSnat, httpGet, d, m, false)
			if err != nil {
				return err
			}
		} else {
			snat := d.Get("snat")
			err := natListCommand(cidr.(string), snat.(*schema.Set).List(), strSnat, httpGet, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			oldDnat, _ := d.GetChange("dnat")
			err := natListCommand(cidr.(string), oldDnat.(*schema.Set).List(), strDnat, httpGet, d, m, false)
			if err != nil {
				return err
			}
		} else {
			dnat := d.Get("dnat")
			err := natListCommand(cidr.(string), dnat.(*schema.Set).List(), strDnat, httpGet, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func natRemoveOnCIDR(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("snat") {
			oldSnat, _ := d.GetChange("snat")
			err := natListCommand(cidr.(string), oldSnat.(*schema.Set).List(), strSnat, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			snat := d.Get("snat")
			err := natListCommand(cidr.(string), snat.(*schema.Set).List(), strSnat, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			oldDnat, _ := d.GetChange("dnat")
			err := natListCommand(cidr.(string), oldDnat.(*schema.Set).List(), strDnat, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			dnat := d.Get("dnat")
			err := natListCommand(cidr.(string), dnat.(*schema.Set).List(), strDnat, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func natAddOnCIDR(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		err := checkCIDRBlocksString(cidr.(string), ipv4ver)
		if err != nil {
			return err
		}
		if d.HasChange("snat") {
			oldSnat, newSnat := d.GetChange("snat")
			oldSnatSetDiff := oldSnat.(*schema.Set).Difference(newSnat.(*schema.Set))
			newSnatSetDiff := newSnat.(*schema.Set).Difference(oldSnat.(*schema.Set))

			oldSnatSetDiffExpanded := expandCIDRInNatList(oldSnatSetDiff.List(), strSnat, ipv4ver)
			newSnatSetDiffExpanded := expandCIDRInNatList(newSnatSetDiff.List(), strSnat, ipv4ver)
			oldSnatSetExpandedRemove := computeOutSlicesOfMap(oldSnatSetDiffExpanded, newSnatSetDiffExpanded)

			err := checkNat(newSnat.(*schema.Set).List())
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), oldSnatSetExpandedRemove, strSnat, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), newSnat.(*schema.Set).List(), strSnat, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := checkNat(d.Get("snat").(*schema.Set).List())
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), d.Get("snat").(*schema.Set).List(), strSnat, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			oldDnat, newDnat := d.GetChange("dnat")
			oldDnatSetDiff := oldDnat.(*schema.Set).Difference(newDnat.(*schema.Set))
			newDnatSetDiff := newDnat.(*schema.Set).Difference(oldDnat.(*schema.Set))

			oldDnatSetDiffExpand := expandCIDRInNatList(oldDnatSetDiff.List(), strDnat, ipv4ver)
			newDnatSetDiffExpand := expandCIDRInNatList(newDnatSetDiff.List(), strDnat, ipv4ver)
			oldDnatSetExpandedRemove := computeOutSlicesOfMap(oldDnatSetDiffExpand, newDnatSetDiffExpand)

			err := checkNat(newDnat.(*schema.Set).List())
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), oldDnatSetExpandedRemove, strDnat, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), newDnat.(*schema.Set).List(), strDnat, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := checkNat(d.Get("dnat").(*schema.Set).List())
			if err != nil {
				return err
			}
			err = natListCommand(cidr.(string), d.Get("dnat").(*schema.Set).List(), strDnat, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func natListCommand(onCIDR string, natList []interface{}, way string, method string,
	d *schema.ResourceData, m interface{}, cidrExpanded bool) error {
	switch method {
	case httpGet:
		if cidrExpanded {
			return fmt.Errorf("internal error : natListCommand Get with cidrExpanded")
		}
		var saves []map[string]interface{}
		for _, natElement := range natList {
			natOK := true
			natOKnoPos := false
			natExpanded := expandCIDRInNat(natElement, way, ipv4ver)
			for _, natExpandedElement := range natExpanded {
				err := natCmd(onCIDR, natExpandedElement, httpGet, m)
				if err != nil {
					if !strings.Contains(err.Error(), noExists) {
						return err
					}
					natOK = false
					if err.Error() == noExistsNoPosErr {
						natOKnoPos = true
					}
				}
			}
			if natOK {
				saves = append(saves, natElement.(map[string]interface{}))
			}
			if natOKnoPos {
				natElementNew := natElement.(map[string]interface{})
				natElementNew["position"] = "?"
				saves = append(saves, natElementNew)
			}
		}
		switch way {
		case strSnat:
			tfErr := d.Set("snat", saves)
			if tfErr != nil {
				panic(tfErr)
			}
		case strDnat:
			tfErr := d.Set("dnat", saves)
			if tfErr != nil {
				panic(tfErr)
			}
		}

		return nil
	case httpDel:
		if cidrExpanded {
			for _, natElement := range natList {
				err := natCmd(onCIDR, natElement, httpDel, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, natElement := range natList {
				natExpanded := expandCIDRInNat(natElement, way, ipv4ver)
				for _, natExpandedElement := range natExpanded {
					err := natCmd(onCIDR, natExpandedElement, httpDel, m)
					if err != nil {
						return err
					}
				}
			}
		}

		return nil
	case httpPut:
		if cidrExpanded {
			for _, natElement := range natList {
				err := checkCIDRBlocksInMap(natElement.(map[string]interface{}), ipv4ver)
				if err != nil {
					return err
				}
				err = natCmd(onCIDR, natElement, httpPut, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, natElement := range natList {
				natExpand := expandCIDRInNat(natElement, way, ipv4ver)
				for _, natExpandElement := range natExpand {
					err := checkCIDRBlocksInMap(natExpandElement.(map[string]interface{}), ipv4ver)
					if err != nil {
						return err
					}
					err = natCmd(onCIDR, natExpandElement, httpPut, m)
					if err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	return fmt.Errorf("internal error : unknown method for natListCommand")
}

func natCmd(onCIDR string, nat interface{}, method string, m interface{}) error {
	client := m.(*Client)

	ma := nat.(map[string]interface{})
	var dstOk string
	var srcOk string
	var natRule Rule
	var natRuleNoPos Rule
	if (ma["to_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
		return fmt.Errorf("need protocol for to_port specification")
	}
	switch ma["action"].(string) {
	case strSnat:
		maskOk := strings.Contains(onCIDR, "/")
		if maskOk {
			srcOk = onCIDR
		} else {
			srcOk = strings.Join([]string{onCIDR, "/32"}, "")
		}
		maskOk = strings.Contains(ma["cidr_blocks"].(string), "/")
		if maskOk {
			dstOk = ma["cidr_blocks"].(string)
		} else {
			dstOk = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
		}
		natRule = Rule{
			Action:    ma["action"].(string),
			Chain:     "POSTROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/32", ""),
			NthEvery:  ma["nth_every"].(string),
			NthPacket: ma["nth_packet"].(string),
			Position:  ma["position"].(string),
			Except:    ma["except"].(bool),
		}
		natRuleNoPos = Rule{
			Action:    ma["action"].(string),
			Chain:     "POSTROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/32", ""),
			NthEvery:  ma["nth_every"].(string),
			NthPacket: ma["nth_packet"].(string),
			Position:  "?",
			Except:    ma["except"].(bool),
		}
	case strDnat:
		maskOk := strings.Contains(onCIDR, "/")
		if maskOk {
			dstOk = onCIDR
		} else {
			dstOk = strings.Join([]string{onCIDR, "/32"}, "")
		}
		maskOk = strings.Contains(ma["cidr_blocks"].(string), "/")
		if maskOk {
			srcOk = ma["cidr_blocks"].(string)
		} else {
			srcOk = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
		}
		natRule = Rule{
			Action:    ma["action"].(string),
			Chain:     "PREROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/32", ""),
			NthEvery:  ma["nth_every"].(string),
			NthPacket: ma["nth_packet"].(string),
			Position:  ma["position"].(string),
			Except:    ma["except"].(bool),
		}
		natRuleNoPos = Rule{
			Action:    ma["action"].(string),
			Chain:     "PREROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/32", ""),
			NthEvery:  ma["nth_every"].(string),
			NthPacket: ma["nth_packet"].(string),
			Position:  "?",
			Except:    ma["except"].(bool),
		}
	}

	switch method {
	case httpDel:
		natExistsNoPos, err := client.natAPIV4(natRuleNoPos, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %s", onCIDR, natRuleNoPos, err)
		}
		if natExistsNoPos {
			ret, err := client.natAPIV4(natRuleNoPos, httpDel)
			if !ret || err != nil {
				return fmt.Errorf("delete rules nat %s %v failed : %s", onCIDR, natRuleNoPos, err)
			}
		}
	case httpPut:
		natExists, err := client.natAPIV4(natRule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %s", onCIDR, natRule, err)
		}
		if !natExists {
			if ma["position"].(string) != "?" {
				natExistsNoPos, err := client.natAPIV4(natRuleNoPos, httpGet)
				if err != nil {
					return fmt.Errorf("check rules nat for %s %v failed : %s", onCIDR, natRuleNoPos, err)
				}
				if natExistsNoPos {
					ret, err := client.natAPIV4(natRuleNoPos, httpDel)
					if !ret || err != nil {
						return fmt.Errorf("delete rules with bad position on nat %s %v failed : %s", onCIDR, natRuleNoPos, err)
					}
					ret, err = client.natAPIV4(natRule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules nat %s %v failed : %s", onCIDR, natRule, err)
					}
				} else {
					ret, err := client.natAPIV4(natRule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules nat %s %v failed : %s", onCIDR, natRule, err)
					}
				}
			} else {
				ret, err := client.natAPIV4(natRule, httpPut)
				if !ret || err != nil {
					return fmt.Errorf("add rules nat %s %v failed : %s", onCIDR, natRule, err)
				}
			}
		}
	case httpGet:
		natExists, err := client.natAPIV4(natRule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %s", onCIDR, natRule, err)
		}
		if !natExists {
			natExistsNoPos, err := client.natAPIV4(natRuleNoPos, httpGet)
			if err != nil {
				return fmt.Errorf("check rules nat for %s %v failed : %s", onCIDR, natRuleNoPos, err)
			}
			if natExistsNoPos {
				return fmt.Errorf(noExistsNoPosErr)
			}

			return fmt.Errorf(noExists)
		}
	}

	return nil
}
