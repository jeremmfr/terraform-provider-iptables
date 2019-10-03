package iptables

import (
	"errors"
	"fmt"
	"log"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform/helper/schema"
)

func resourceRaw() *schema.Resource {
	return &schema.Resource{
		Create: resourceRawCreate,
		Read:   resourceRawRead,
		Update: resourceRawUpdate,
		Delete: resourceRawDelete,
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
							Default:      "0.0.0.0/0",
							ValidateFunc: validateCIDRNetworkOrHostV4(),
						},
						"dst_cidr_blocks": {
							Type:         schema.TypeString,
							Optional:     true,
							StateFunc:    protocolStateFunc,
							Default:      "0.0.0.0/0",
							ValidateFunc: validateCIDRNetworkOrHostV4(),
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

func resourceRawCreate(d *schema.ResourceData, m interface{}) error {
	err := resourceRawUpdate(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!")
	return nil
}

func resourceRawRead(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("rule") {
		oraw, _ := d.GetChange("rule")
		osraw := oraw.(*schema.Set)
		err := rawRule(osraw.List(), httpGet, m)
		if err != nil {
			d.SetId("")
		}
	} else {
		log.Print("no change")
		oraw := d.Get("rule")
		osraw := oraw.(*schema.Set)
		err := rawRule(osraw.List(), httpGet, m)
		if err != nil {
			d.SetId("")
		}
	}
	return nil
}

func resourceRawUpdate(d *schema.ResourceData, m interface{}) error {
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
		err := rawRule(oldRuleSetRemove, httpDel, m)
		if err != nil {
			d.SetId("")
			return err
		}
		err = rawRule(newRuleSet.List(), httpPut, m)
		if err != nil {
			d.SetId("")
			return err
		}
	}
	client := m.(*Client)
	err := client.saveV4()
	if err != nil {
		return fmt.Errorf("iptables save failed : %s", err)
	}
	return nil
}

func resourceRawDelete(d *schema.ResourceData, m interface{}) error {
	rule := d.Get("rule")
	ruleSet := rule.(*schema.Set)
	err := rawRule(ruleSet.List(), httpDel, m)
	if err != nil {
		return err
	}
	client := m.(*Client)
	err = client.saveV4()
	if err != nil {
		return fmt.Errorf("iptables save failed : %s", err)
	}
	return nil
}

func rawRule(ruleList []interface{}, method string, m interface{}) error {
	client := m.(*Client)

	for _, rule := range ruleList {
		ma := rule.(map[string]interface{})
		var dstOk string
		var srcOk string
		var actionOk string
		var logprefixOk string

		matched := strings.Contains(ma["src_cidr_blocks"].(string), "/")
		if !matched {
			srcOk = strings.Join([]string{ma["src_cidr_blocks"].(string), "/32"}, "")
		} else {
			srcOk = ma["src_cidr_blocks"].(string)
		}
		matched = strings.Contains(ma["dst_cidr_blocks"].(string), "/")
		if !matched {
			dstOk = strings.Join([]string{ma["dst_cidr_blocks"].(string), "/32"}, "")
		} else {
			dstOk = ma["dst_cidr_blocks"].(string)
		}

		if strings.Contains(ma["action"].(string), "LOG --log-prefix") {
			f := func(c rune) bool {
				return !unicode.IsLetter(c) && !unicode.IsNumber(c)
			}
			words := strings.FieldsFunc(ma["action"].(string), f)
			if len(words) != 4 {
				return fmt.Errorf("too many words with log-prefix : one only")
			}
			actionOk = words[0]
			logprefixOk = words[3]
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
			IPSrc:     strings.Replace(srcOk, "/", "_", -1),
			IPDst:     strings.Replace(dstOk, "/", "_", -1),
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
			IPSrc:     strings.Replace(srcOk, "/", "_", -1),
			IPDst:     strings.Replace(dstOk, "/", "_", -1),
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
			ruleexistsNoPos, err := client.rawAPIV4(ruleNoPos, httpGet)
			if err != nil {
				return fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if ruleexistsNoPos {
				ret, err := client.rawAPIV4(ruleNoPos, httpDel)
				if !ret || err != nil {
					return fmt.Errorf("delete rules on raw %s failed : %s", ma, err)
				}
			}
		case httpPut:
			ruleexists, err := client.rawAPIV4(rule, httpGet)
			if err != nil {
				return fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if !ruleexists {
				if ma["position"].(string) != "?" {
					ruleexistsNoPos, err := client.rawAPIV4(ruleNoPos, httpGet)
					if err != nil {
						return fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
					}
					if ruleexistsNoPos {
						ret, err := client.rawAPIV4(ruleNoPos, httpDel)
						if !ret || err != nil {
							return fmt.Errorf("delete rules with bad position on raw %s failed : %s", ma, err)
						}
						ret, err = client.rawAPIV4(rule, httpPut)
						if !ret || err != nil {
							return fmt.Errorf("add rules on raw %s failed : %s", ma, err)
						}
					} else {
						ret, err := client.rawAPIV4(rule, httpPut)
						if !ret || err != nil {
							return fmt.Errorf("add rules on raw %s failed %s", ma, err)
						}
					}
				} else {
					ret, err := client.rawAPIV4(rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules on raw %s failed : %s", ma, err)
					}
				}
			}
		case httpGet:
			ruleexists, err := client.rawAPIV4(rule, httpGet)
			if err != nil {
				return fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if !ruleexists {
				return errors.New("no_exist")
			}
		}
	}
	return nil
}
