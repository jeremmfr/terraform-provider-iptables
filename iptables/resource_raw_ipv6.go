package iptables

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRawIPv6() *schema.Resource {
	return &schema.Resource{
		Create: resourceRawIPv6Create,
		Read:   resourceRawIPv6Read,
		Update: resourceRawIPv6Update,
		Delete: resourceRawIPv6Delete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"rule": {
				Type:     schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"chain": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "PREROUTING",
						},
						"protocol": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: protocolStateFunc,
							Default:   "all",
						},
						"from_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"to_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
						},
						"src_cidr_blocks": {
							Type:         schema.TypeString,
							Optional:     true,
							StateFunc:    protocolStateFunc,
							Default:      "::/0",
							ValidateFunc: validateCIDRNetworkOrHostV6(),
						},
						"dst_cidr_blocks": {
							Type:         schema.TypeString,
							Optional:     true,
							StateFunc:    protocolStateFunc,
							Default:      "::/0",
							ValidateFunc: validateCIDRNetworkOrHostV6(),
						},
						"iface_out": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: ifaceStateFunc,
							Default:   "*",
						},
						"iface_in": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: ifaceStateFunc,
							Default:   "*",
						},
						"action": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "ACCEPT",
						},
						"tcpflags_mask": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "SYN,RST,ACK,FIN",
						},
						"tcpflags_comp": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"notrack": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"tcpmss": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"position": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "?",
						},
					},
				},
			},
		},
	}
}

func resourceRawIPv6Create(d *schema.ResourceData, m interface{}) error {
	err := resourceRawIPv6Update(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceRawIPv6Read(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("rule") {
		oraw, _ := d.GetChange("rule")
		osraw := oraw.(*schema.Set)
		rawList, err := rawRuleV6(osraw.List(), httpGet, m)
		if err != nil {
			return err
		}
		tfErr := d.Set("rule", rawList)
		if tfErr != nil {
			panic(tfErr)
		}
	} else {
		raw := d.Get("rule")
		sraw := raw.(*schema.Set)
		rawList, err := rawRuleV6(sraw.List(), httpGet, m)
		if err != nil {
			return err
		}
		tfErr := d.Set("rule", rawList)
		if tfErr != nil {
			panic(tfErr)
		}
	}

	return nil
}

func resourceRawIPv6Update(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}

	if d.HasChange("rule") {
		oldRule, newRule := d.GetChange("rule")
		oldRuleSet := oldRule.(*schema.Set)
		newRuleSet := newRule.(*schema.Set)
		oldRuleSetDiff := oldRuleSet.Difference(newRuleSet)
		newRuleSetDiff := newRuleSet.Difference(oldRuleSet)

		oldRuleSetRemove := computeOutSlicesOfMap(oldRuleSetDiff.List(), newRuleSetDiff.List())
		_, err := rawRuleV6(oldRuleSetRemove, httpDel, m)
		if err != nil {
			d.SetId("")

			return err
		}
		_, err = rawRuleV6(newRuleSet.List(), httpPut, m)
		if err != nil {
			d.SetId("")

			return err
		}
	}
	client := m.(*Client)
	if err := client.saveV6(); err != nil {
		return fmt.Errorf("ip6tables save failed : %s", err)
	}

	return nil
}

func resourceRawIPv6Delete(d *schema.ResourceData, m interface{}) error {
	rule := d.Get("rule")
	ruleSet := rule.(*schema.Set)
	_, err := rawRuleV6(ruleSet.List(), httpDel, m)
	if err != nil {
		return err
	}
	client := m.(*Client)
	err = client.saveV6()
	if err != nil {
		return fmt.Errorf("ip6tables save failed : %s", err)
	}

	return nil
}

func rawRuleV6(ruleList []interface{}, method string, m interface{}) ([]interface{}, error) {
	client := m.(*Client)
	if !client.IPv6 {
		return nil, fmt.Errorf("ipv6 not enable on provider")
	}

	var ruleListReturn []interface{}
	for _, rule := range ruleList {
		ma := rule.(map[string]interface{})
		var dstOk string
		var srcOk string
		var actionOk string
		var logprefixOk string

		matched := strings.Contains(ma["src_cidr_blocks"].(string), "/")
		if !matched {
			srcOk = strings.Join([]string{ma["src_cidr_blocks"].(string), "/128"}, "")
		} else {
			srcOk = ma["src_cidr_blocks"].(string)
		}
		matched = strings.Contains(ma["dst_cidr_blocks"].(string), "/")
		if !matched {
			dstOk = strings.Join([]string{ma["dst_cidr_blocks"].(string), "/128"}, "")
		} else {
			dstOk = ma["dst_cidr_blocks"].(string)
		}

		if strings.Contains(ma["action"].(string), "LOG --log-prefix") {
			actionSplit := strings.Split(ma["action"].(string), " ")
			if len(actionSplit) != numWordForLogPrefix {
				return nil, fmt.Errorf("too many words with log-prefix : one only")
			}
			actionOk = actionSplit[0]
			logprefixOk = actionSplit[2]
		} else {
			actionOk = ma["action"].(string)
			logprefixOk = ""
		}

		rule := Rule{
			Action:    actionOk,
			Chain:     ma["chain"].(string),
			Proto:     ma["protocol"].(string),
			IfaceIn:   ma["iface_in"].(string),
			IfaceOut:  ma["iface_out"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Sports:    ma["from_port"].(string),
			Dports:    ma["to_port"].(string),
			Tcpflags1: ma["tcpflags_mask"].(string),
			Tcpflags2: ma["tcpflags_comp"].(string),
			Notrack:   ma["notrack"].(bool),
			Position:  ma["position"].(string),
			Logprefix: logprefixOk,
			Tcpmss:    ma["tcpmss"].(string),
		}
		ruleNoPos := Rule{
			Action:    actionOk,
			Chain:     ma["chain"].(string),
			Proto:     ma["protocol"].(string),
			IfaceIn:   ma["iface_in"].(string),
			IfaceOut:  ma["iface_out"].(string),
			IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
			IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
			Sports:    ma["from_port"].(string),
			Dports:    ma["to_port"].(string),
			Tcpflags1: ma["tcpflags_mask"].(string),
			Tcpflags2: ma["tcpflags_comp"].(string),
			Notrack:   ma["notrack"].(bool),
			Position:  "?",
			Logprefix: logprefixOk,
			Tcpmss:    ma["tcpmss"].(string),
		}

		switch method {
		case httpDel:
			ruleexistsNoPos, err := client.rawAPIV6(ruleNoPos, httpGet)
			if err != nil {
				return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if ruleexistsNoPos {
				ret, err := client.rawAPIV6(ruleNoPos, httpDel)
				if !ret || err != nil {
					return nil, fmt.Errorf("delete rules on raw %s failed : %s", ma, err)
				}
			}
		case httpPut:
			ruleexists, err := client.rawAPIV6(rule, httpGet)
			if err != nil {
				return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if !ruleexists {
				if ma["position"].(string) != "?" {
					ruleexistsNoPos, err := client.rawAPIV6(ruleNoPos, httpGet)
					if err != nil {
						return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
					}
					if ruleexistsNoPos {
						ret, err := client.rawAPIV6(ruleNoPos, httpDel)
						if !ret || err != nil {
							return nil, fmt.Errorf("delete rules with bad position on raw %s failed : %s", ma, err)
						}
						ret, err = client.rawAPIV6(rule, httpPut)
						if !ret || err != nil {
							return nil, fmt.Errorf("add rules on raw %s failed : %s", ma, err)
						}
					} else {
						ret, err := client.rawAPIV6(rule, httpPut)
						if !ret || err != nil {
							return nil, fmt.Errorf("add rules on raw %s failed : %s", ma, err)
						}
					}
				} else {
					ret, err := client.rawAPIV6(rule, httpPut)
					if !ret || err != nil {
						return nil, fmt.Errorf("add rules on raw %s failed : %s", ma, err)
					}
				}
			}
		case httpGet:
			ruleexists, err := client.rawAPIV6(rule, httpGet)
			if err != nil {
				return ruleListReturn, fmt.Errorf("check rules on raw for %v failed : %w", rule, err)
			}
			if ruleexists {
				ruleListReturn = append(ruleListReturn, ma)
			} else {
				ruleexistsNoPos, err := client.rawAPIV6(ruleNoPos, httpGet)
				if err != nil {
					return ruleListReturn, fmt.Errorf("check rules on raw for %v failed : %w", ruleNoPos, err)
				}
				if ruleexistsNoPos {
					ma["position"] = "?"
					ruleListReturn = append(ruleListReturn, ma)
				}
			}
		}
	}

	return ruleListReturn, nil
}
