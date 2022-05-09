package iptables

import (
	"bytes"
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceNatIPv6() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceNatIPv6Create,
		ReadContext:   resourceNatIPv6Read,
		UpdateContext: resourceNatIPv6Update,
		DeleteContext: resourceNatIPv6Delete,
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
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: validateCIDRNetworkOrHostV6(),
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
				Set: natHashV6,
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
							Type:             schema.TypeString,
							Optional:         true,
							ValidateDiagFunc: validateCIDRNetworkOrHostV6(),
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
				Set: natHashV6,
			},
		},
	}
}

func resourceNatIPv6Create(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	diags := resourceNatIPv6Update(ctx, d, m)
	if len(diags) > 0 {
		return diags
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceNatIPv6Read(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, _ := d.GetChange("on_cidr_blocks")
		err := natReadOnCIDRV6(ctx, oldOnCIDR.(*schema.Set).List(), d, m)
		if err != nil {
			return diag.FromErr(err)
		}
	} else {
		err := natReadOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			return diag.FromErr(err)
		}
	}
	if (len(d.Get("snat").(*schema.Set).List()) == 0) && (len(d.Get("dnat").(*schema.Set).List()) == 0) {
		d.SetId("")
	}

	return nil
}

func resourceNatIPv6Update(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}

	err := checkNatPositionAndCIDRList(d)
	if err != nil {
		d.SetId("")

		return diag.FromErr(err)
	}
	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, newOnCIDR := d.GetChange("on_cidr_blocks")
		onCIDRRemove := computeRemove(oldOnCIDR.(*schema.Set).List(), newOnCIDR.(*schema.Set).List())

		err = natRemoveOnCIDRV6(ctx, onCIDRRemove, d, m)
		if err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
		err = natAddOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
	} else {
		err = natAddOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
	}
	client := m.(*Client)
	err = client.saveV6(ctx)
	if err != nil {
		return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
	}

	return nil
}

func resourceNatIPv6Delete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	err := natRemoveOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
	if err != nil {
		d.SetId(d.Get("name").(string) + "!")

		return diag.FromErr(err)
	}
	client := m.(*Client)
	err = client.saveV6(ctx)
	if err != nil {
		return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
	}

	return nil
}

func natHashV6(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%s-", m["to_port"].(string)))
	p := protocolForValue(m["protocol"].(string))
	buf.WriteString(fmt.Sprintf("%s-", p))
	buf.WriteString(fmt.Sprintf("%s-", strings.ReplaceAll(m["nat_ip"].(string), "/128", "")))
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

	return hashcodeString(buf.String())
}

func natReadOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	snat := d.Get("snat").(*schema.Set).List()
	if d.HasChange("snat") {
		oldSnat, _ := d.GetChange("snat")
		snat = oldSnat.(*schema.Set).List()
	}
	dnat := d.Get("dnat").(*schema.Set).List()
	if d.HasChange("dnat") {
		oldDnat, _ := d.GetChange("dnat")
		dnat = oldDnat.(*schema.Set).List()
	}
	for _, cidr := range onCIDRList {
		// snat
		snatRead, err := natListCommandV6(ctx, cidr.(string), snat, strSnat, httpGet, m, false)
		if err != nil {
			return err
		}
		snat = make([]interface{}, len(snatRead))
		copy(snat, snatRead)
		if tfErr := d.Set("snat", snatRead); tfErr != nil {
			panic(tfErr)
		}
		// dnat
		dnatRead, err := natListCommandV6(ctx, cidr.(string), dnat, strDnat, httpGet, m, false)
		if err != nil {
			return err
		}
		dnat = make([]interface{}, len(dnatRead))
		copy(dnat, dnatRead)
		if tfErr := d.Set("dnat", dnatRead); tfErr != nil {
			panic(tfErr)
		}
	}

	return nil
}

func natRemoveOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("snat") {
			oldSnat, _ := d.GetChange("snat")
			if _, err := natListCommandV6(
				ctx, cidr.(string), oldSnat.(*schema.Set).List(), strSnat, httpDel, m, false); err != nil {
				return err
			}
		} else {
			if _, err := natListCommandV6(
				ctx, cidr.(string), d.Get("snat").(*schema.Set).List(), strSnat, httpDel, m, false); err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			oldDnat, _ := d.GetChange("dnat")
			if _, err := natListCommandV6(
				ctx, cidr.(string), oldDnat.(*schema.Set).List(), strDnat, httpDel, m, false); err != nil {
				return err
			}
		} else {
			if _, err := natListCommandV6(
				ctx, cidr.(string), d.Get("dnat").(*schema.Set).List(), strDnat, httpDel, m, false); err != nil {
				return err
			}
		}
	}

	return nil
}

func natAddOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		err := checkCIDRBlocksString(cidr.(string), ipv6ver)
		if err != nil {
			return err
		}
		if d.HasChange("snat") {
			oldSnat, newSnat := d.GetChange("snat")
			oldSnatSetDiff := oldSnat.(*schema.Set).Difference(newSnat.(*schema.Set))
			newSnatSetDiff := newSnat.(*schema.Set).Difference(oldSnat.(*schema.Set))

			oldSnatSetDiffExpanded := expandCIDRInNatList(oldSnatSetDiff.List(), strSnat, ipv6ver)
			newSnatSetDiffExpanded := expandCIDRInNatList(newSnatSetDiff.List(), strSnat, ipv6ver)
			oldSnatSetExpandedRemove := computeOutSlicesOfMap(oldSnatSetDiffExpanded, newSnatSetDiffExpanded)

			err := checkNat(newSnat.(*schema.Set).List())
			if err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), oldSnatSetExpandedRemove, strSnat, httpDel, m, true); err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), newSnat.(*schema.Set).List(), strSnat, httpPut, m, false); err != nil {
				return err
			}
		} else {
			err := checkNat(d.Get("snat").(*schema.Set).List())
			if err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), d.Get("snat").(*schema.Set).List(), strSnat, httpPut, m, false); err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			oldDnat, newDnat := d.GetChange("dnat")
			oldDnatSetDiff := oldDnat.(*schema.Set).Difference(newDnat.(*schema.Set))
			newDnatSetDiff := newDnat.(*schema.Set).Difference(oldDnat.(*schema.Set))

			oldDnatSetDiffExpanded := expandCIDRInNatList(oldDnatSetDiff.List(), strDnat, ipv6ver)
			newDnatSetDiffExpanded := expandCIDRInNatList(newDnatSetDiff.List(), strDnat, ipv6ver)
			oldDnatSetExpandedRemove := computeOutSlicesOfMap(oldDnatSetDiffExpanded, newDnatSetDiffExpanded)

			err := checkNat(newDnat.(*schema.Set).List())
			if err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), oldDnatSetExpandedRemove, strDnat, httpDel, m, true); err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), newDnat.(*schema.Set).List(), strDnat, httpPut, m, false); err != nil {
				return err
			}
		} else {
			err := checkNat(d.Get("dnat").(*schema.Set).List())
			if err != nil {
				return err
			}
			if _, err := natListCommandV6(
				ctx, cidr.(string), d.Get("dnat").(*schema.Set).List(), strDnat, httpPut, m, false); err != nil {
				return err
			}
		}
	}

	return nil
}

func natListCommandV6(
	ctx context.Context,
	onCIDR string,
	natList []interface{},
	way, method string,
	m interface{},
	cidrExpanded bool,
) ([]interface{}, error) {
	switch method {
	case httpGet:
		if cidrExpanded {
			return nil, fmt.Errorf("internal error : natListCommand Get with cidrExpanded")
		}
		var saves []interface{}
		for _, natElement := range natList {
			natOK := true
			natOKnoPos := false
			natExpanded := expandCIDRInNat(natElement, way, ipv6ver)
			for _, natExpandedElement := range natExpanded {
				err := natCmdV6(ctx, onCIDR, natExpandedElement, httpGet, m)
				if err != nil {
					if !strings.Contains(err.Error(), noExists) {
						return nil, err
					}
					natOK = false
					if err.Error() == noExistsNoPosErr {
						natOKnoPos = true
					}
				}
			}
			if natOK {
				saves = append(saves, natElement)
			}
			if natOKnoPos {
				natElement.(map[string]interface{})["position"] = "?"
				saves = append(saves, natElement)
			}
		}

		return saves, nil
	case httpDel:
		if cidrExpanded {
			for _, natElement := range natList {
				err := natCmdV6(ctx, onCIDR, natElement, httpDel, m)
				if err != nil {
					return nil, err
				}
			}
		} else {
			for _, natElement := range natList {
				natExpanded := expandCIDRInNat(natElement, way, ipv6ver)
				for _, natExpandedElement := range natExpanded {
					err := natCmdV6(ctx, onCIDR, natExpandedElement, httpDel, m)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		return nil, nil
	case httpPut:
		if cidrExpanded {
			for _, natElement := range natList {
				err := checkCIDRBlocksInMap(natElement.(map[string]interface{}), ipv6ver)
				if err != nil {
					return nil, err
				}
				err = natCmdV6(ctx, onCIDR, natElement, httpPut, m)
				if err != nil {
					return nil, err
				}
			}
		} else {
			for _, natElement := range natList {
				natExpand := expandCIDRInNat(natElement, way, ipv6ver)
				for _, natExpandElement := range natExpand {
					err := checkCIDRBlocksInMap(natExpandElement.(map[string]interface{}), ipv6ver)
					if err != nil {
						return nil, err
					}
					err = natCmdV6(ctx, onCIDR, natExpandElement, httpPut, m)
					if err != nil {
						return nil, err
					}
				}
			}
		}

		return nil, nil
	}

	return nil, fmt.Errorf("internal error : unknown method for natListCommand")
}

func natCmdV6(ctx context.Context, onCIDR string, nat interface{}, method string, m interface{}) error {
	client := m.(*Client)
	if !client.IPv6 {
		return fmt.Errorf("ipv6 not enable on provider")
	}

	ma := nat.(map[string]interface{})
	err := checkCIDRBlocksInMap(ma, ipv6ver)
	if err != nil {
		return err
	}
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
			srcOk = strings.Join([]string{onCIDR, "/128"}, "")
		}
		maskOk = strings.Contains(ma["cidr_blocks"].(string), "/")
		if maskOk {
			dstOk = ma["cidr_blocks"].(string)
		} else {
			dstOk = strings.Join([]string{ma["cidr_blocks"].(string), "/128"}, "")
		}
		natRule = Rule{
			Action:    ma["action"].(string),
			Chain:     "POSTROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/128", ""),
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
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/128", ""),
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
			dstOk = strings.Join([]string{onCIDR, "/128"}, "")
		}
		maskOk = strings.Contains(ma["cidr_blocks"].(string), "/")
		if maskOk {
			srcOk = ma["cidr_blocks"].(string)
		} else {
			srcOk = strings.Join([]string{ma["cidr_blocks"].(string), "/128"}, "")
		}
		natRule = Rule{
			Action:    ma["action"].(string),
			Chain:     "PREROUTING",
			Proto:     ma["protocol"].(string),
			Iface:     ma["iface"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Dports:    ma["to_port"].(string),
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/128", ""),
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
			IPNat:     strings.ReplaceAll(ma["nat_ip"].(string), "/128", ""),
			NthEvery:  ma["nth_every"].(string),
			NthPacket: ma["nth_packet"].(string),
			Position:  "?",
			Except:    ma["except"].(bool),
		}
	}

	switch method {
	case httpDel:
		natExistsNoPos, err := client.natAPIV6(ctx, natRuleNoPos, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %w", onCIDR, natRuleNoPos, err)
		}
		if natExistsNoPos {
			ret, err := client.natAPIV6(ctx, natRuleNoPos, httpDel)
			if !ret || err != nil {
				return fmt.Errorf("delete rules nat %s %v failed : %w", onCIDR, natRuleNoPos, err)
			}
		}
	case httpPut:
		natExists, err := client.natAPIV6(ctx, natRule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %w", onCIDR, natRule, err)
		}
		if !natExists {
			if ma["position"].(string) != "?" {
				natExistsNoPos, err := client.natAPIV6(ctx, natRuleNoPos, httpGet)
				if err != nil {
					return fmt.Errorf("check rules nat for %s %v failed : %w", onCIDR, natRuleNoPos, err)
				}
				if natExistsNoPos {
					ret, err := client.natAPIV6(ctx, natRuleNoPos, httpDel)
					if !ret || err != nil {
						return fmt.Errorf("delete rules with bad position on nat %s %v failed : %w", onCIDR, natRuleNoPos, err)
					}
					ret, err = client.natAPIV6(ctx, natRule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules nat %s %v failed : %w", onCIDR, natRule, err)
					}
				} else {
					ret, err := client.natAPIV6(ctx, natRule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules nat %s %v failed : %w", onCIDR, natRule, err)
					}
				}
			} else {
				ret, err := client.natAPIV6(ctx, natRule, httpPut)
				if !ret || err != nil {
					return fmt.Errorf("add rules nat %s %v failed : %w", onCIDR, natRule, err)
				}
			}
		}
	case httpGet:
		natExists, err := client.natAPIV6(ctx, natRule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules nat for %s %v failed : %w", onCIDR, natRule, err)
		}
		if !natExists {
			natExistsNoPos, err := client.natAPIV4(ctx, natRuleNoPos, httpGet)
			if err != nil {
				return fmt.Errorf("check rules nat for %s %v failed : %w", onCIDR, natRuleNoPos, err)
			}
			if natExistsNoPos {
				return fmt.Errorf(noExistsNoPosErr)
			}

			return fmt.Errorf(noExists)
		}
	}

	return nil
}
