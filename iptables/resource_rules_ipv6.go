package iptables

import (
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/helper/schema"
)

func resourceRulesIPv6() *schema.Resource {
	return &schema.Resource{
		Create: resourceRulesIPv6Create,
		Read:   resourceRulesIPv6Read,
		Update: resourceRulesIPv6Update,
		Delete: resourceRulesIPv6Delete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
			},
			"project": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
			},
			"on_cidr_blocks": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"ingress": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
							ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
								value := v.(string)
								listlen := len(strings.Split(value, ","))
								if listlen > maxElementsForListPorts {
									errors = append(errors, fmt.Errorf("%q too many ports specified : %v", k, value))
								}

								return
							},
						},
						"to_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
							ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
								value := v.(string)
								listlen := len(strings.Split(value, ","))
								if listlen > maxElementsForListPorts {
									errors = append(errors, fmt.Errorf("%q too many ports specified : %v", k, value))
								}

								return
							},
						},
						"protocol": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: protocolStateFunc,
							Default:   "all",
						},
						"cidr_blocks": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
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
						"state": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"icmptype": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"fragment": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"action": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "ACCEPT",
						},
						"position": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "?",
						},
					},
				},
				Set: ruleHash,
			},
			"egress": {
				Type:     schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "0",
							ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
								value := v.(string)
								listlen := len(strings.Split(value, ","))
								if listlen > maxElementsForListPorts {
									errors = append(errors, fmt.Errorf("%q too many ports specified : %v", k, value))
								}

								return
							},
						},
						"to_port": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  0,
							ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
								value := v.(string)
								listlen := len(strings.Split(value, ","))
								if listlen > maxElementsForListPorts {
									errors = append(errors, fmt.Errorf("%q too many ports specified : %v", k, value))
								}

								return
							},
						},
						"protocol": {
							Type:      schema.TypeString,
							Optional:  true,
							StateFunc: protocolStateFunc,
							Default:   "all",
						},
						"cidr_blocks": {
							Type:     schema.TypeSet,
							Optional: true,
							Elem:     &schema.Schema{Type: schema.TypeString},
						},
						"iface_out": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "*",
						},
						"iface_in": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "*",
						},
						"state": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"icmptype": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "",
						},
						"fragment": {
							Type:     schema.TypeBool,
							Optional: true,
							Default:  false,
						},
						"action": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "ACCEPT",
						},
						"position": {
							Type:     schema.TypeString,
							Optional: true,
							Default:  "?",
						},
					},
				},
				Set: ruleHash,
			},
		},
	}
}

func resourceRulesIPv6Create(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	if !client.IPv6 {
		return fmt.Errorf("ipv6 not enable on provider")
	}

	checkProcject, err := client.chainAPIV6(d.Get("project").(string), httpGet)
	if err != nil {
		return fmt.Errorf("check project %s failed : %s", d.Get("project"), err)
	}
	if !checkProcject {
		return fmt.Errorf("unknown project %s", d.Get("project"))
	}
	err = resourceRulesIPv6Update(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceRulesIPv6Read(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("project") {
		o, _ := d.GetChange("project")
		if o != "" {
			tfErr := d.Set("project", o)
			if tfErr != nil {
				panic(tfErr)
			}

			return fmt.Errorf("you can't change project")
		}
	}

	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, _ := d.GetChange("on_cidr_blocks")
		err := rulesReadOnCIDRV6(oldOnCIDR.(*schema.Set).List(), d, m)
		if err != nil {
			return err
		}
	} else {
		err := rulesReadOnCIDRV6(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			return err
		}
	}
	if (len(d.Get("ingress").(*schema.Set).List()) == 0) && (len(d.Get("egress").(*schema.Set).List()) == 0) {
		d.SetId("")
	}

	return nil
}

func resourceRulesIPv6Update(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}

	err := checkRulesPositionAndCIDRList(d)
	if err != nil {
		d.SetId("")

		return err
	}
	if d.HasChange("project") {
		o, _ := d.GetChange("project")
		if o != "" {
			d.SetId("")

			return fmt.Errorf("you can't change project")
		}
	}

	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, newOnCIDR := d.GetChange("on_cidr_blocks")
		onCIDRRemove := computeRemove(oldOnCIDR.(*schema.Set).List(), newOnCIDR.(*schema.Set).List())
		err = rulesRemoveOnCIDRV6(onCIDRRemove, d, m)
		if err != nil {
			d.SetId("")

			return err
		}
		err = rulesAddOnCIDRV6(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return err
		}
	} else {
		err = rulesAddOnCIDRV6(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
		if err != nil {
			d.SetId("")

			return err
		}
	}
	client := m.(*Client)
	err = client.saveV6()
	if err != nil {
		return fmt.Errorf("ip6tables save failed : %s", err)
	}

	return nil
}

func resourceRulesIPv6Delete(d *schema.ResourceData, m interface{}) error {
	err := rulesRemoveOnCIDRV6(d.Get("on_cidr_blocks").(*schema.Set).List(), d, m)
	if err != nil {
		d.SetId(d.Get("name").(string) + "!")

		return err
	}
	client := m.(*Client)
	err = client.saveV6()
	if err != nil {
		return fmt.Errorf("ip6tables save failed : %s", err)
	}

	return nil
}

func rulesReadOnCIDRV6(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("ingress") {
			oldIngress, _ := d.GetChange("ingress")
			err := gressListCommandV6(cidr.(string), oldIngress.(*schema.Set).List(), wayIngress, httpGet, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("ingress").(*schema.Set).List(), wayIngress, httpGet, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, _ := d.GetChange("egress")
			err := gressListCommandV6(cidr.(string), oldEgress.(*schema.Set).List(), wayEgress, httpGet, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("egress").(*schema.Set).List(), wayEgress, httpGet, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func rulesRemoveOnCIDRV6(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("ingress") {
			oldIngress, _ := d.GetChange("ingress")
			err := gressListCommandV6(cidr.(string), oldIngress.(*schema.Set).List(), wayIngress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("ingress").(*schema.Set).List(), wayIngress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, _ := d.GetChange("egress")
			err := gressListCommandV6(cidr.(string), oldEgress.(*schema.Set).List(), wayEgress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("egress").(*schema.Set).List(), wayEgress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func rulesAddOnCIDRV6(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		err := checkCIDRBlocksString(cidr.(string), ipv6ver)
		if err != nil {
			return err
		}
		if d.HasChange("ingress") {
			oldIngress, newIngress := d.GetChange("ingress")
			oldIngressSetDiff := oldIngress.(*schema.Set).Difference(newIngress.(*schema.Set))
			newIngressSetDiff := newIngress.(*schema.Set).Difference(oldIngress.(*schema.Set))

			//			Expand for cidr_blocks slices -> string
			oldIngressSetDiffExpanded := expandCIDRInGressList(oldIngressSetDiff.List(), ipv6ver)
			newIngressSetDiffExpanded := expandCIDRInGressList(newIngressSetDiff.List(), ipv6ver)
			//			computation of expanded deleted gress list
			oldIngressSetExpandedRemove := computeOutSlicesOfMap(oldIngressSetDiffExpanded, newIngressSetDiffExpanded)

			err = gressListCommandV6(cidr.(string), oldIngressSetExpandedRemove, wayIngress, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err := gressListCommandV6(cidr.(string), newIngress.(*schema.Set).List(), wayIngress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("ingress").(*schema.Set).List(), wayIngress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, newEgress := d.GetChange("egress")
			oldEgressSetDiff := oldEgress.(*schema.Set).Difference(newEgress.(*schema.Set))
			newEgressSetDiff := newEgress.(*schema.Set).Difference(oldEgress.(*schema.Set))

			//			Expand for cidr_blocks slices -> string
			oldEgressSetDiffExpanded := expandCIDRInGressList(oldEgressSetDiff.List(), ipv6ver)
			newEgressSetDiffExpanded := expandCIDRInGressList(newEgressSetDiff.List(), ipv6ver)
			//			computation of expanded deleted gress list
			oldEgressSetExpandedRemove := computeOutSlicesOfMap(oldEgressSetDiffExpanded, newEgressSetDiffExpanded)

			err := gressListCommandV6(cidr.(string), oldEgressSetExpandedRemove, wayEgress, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err = gressListCommandV6(cidr.(string), newEgress.(*schema.Set).List(), wayEgress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			err := gressListCommandV6(cidr.(string), d.Get("egress").(*schema.Set).List(), wayEgress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
	}

	return nil
}

func gressListCommandV6(onCIDR string, gressList []interface{}, way string, method string,
	d *schema.ResourceData, m interface{}, cidrExpanded bool) error {
	switch method {
	case httpGet:
		if cidrExpanded {
			return fmt.Errorf("internal error : gressListCommand Get with cidrExpanded")
		}
		var saves []map[string]interface{}
		for _, gressElement := range gressList {
			gressOK := true
			gressOKnoPos := false
			gressExpand := expandCIDRInGress(gressElement, ipv6ver)
			for _, gressExpandElement := range gressExpand {
				err := gressCmdV6(onCIDR, gressExpandElement, way, httpGet, d, m)
				if err != nil {
					if !strings.Contains(err.Error(), noExists) {
						return err
					}
					gressOK = false
					if err.Error() == noExistsNoPosErr {
						gressOKnoPos = true
					}
				}
			}
			if gressOK {
				saves = append(saves, gressElement.(map[string]interface{}))
			}
			if gressOKnoPos {
				gressElementNew := gressElement.(map[string]interface{})
				gressElementNew["position"] = "?"
				saves = append(saves, gressElementNew)
			}
		}
		switch way {
		case wayIngress:
			tfErr := d.Set("ingress", saves)
			if tfErr != nil {
				panic(tfErr)
			}
		case wayEgress:
			tfErr := d.Set("egress", saves)
			if tfErr != nil {
				panic(tfErr)
			}
		}

		return nil
	case httpDel:
		if cidrExpanded {
			for _, gressElement := range gressList {
				err := gressCmdV6(onCIDR, gressElement, way, httpDel, d, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv6ver)
				for _, gressExpandElement := range gressExpand {
					err := gressCmdV6(onCIDR, gressExpandElement, way, httpDel, d, m)
					if err != nil {
						return err
					}
				}
			}
		}

		return nil
	case httpPut:
		if cidrExpanded {
			for _, gressElement := range gressList {
				err := checkCIDRBlocksInMap(gressElement.(map[string]interface{}), ipv6ver)
				if err != nil {
					return err
				}
				err = gressCmdV6(onCIDR, gressElement, way, httpPut, d, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv6ver)
				for _, gressExpandElement := range gressExpand {
					err := checkCIDRBlocksInMap(gressExpandElement.(map[string]interface{}), ipv6ver)
					if err != nil {
						return err
					}
					err = gressCmdV6(onCIDR, gressExpandElement, way, httpPut, d, m)
					if err != nil {
						return err
					}
				}
			}
		}

		return nil
	}

	return fmt.Errorf("internal error : unknown method for gressListCommand")
}

func gressCmdV6(onCIDR string, gress interface{}, way string, method string,
	d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	if !client.IPv6 {
		return fmt.Errorf("ipv6 not enable on provider")
	}
	var dstOk string
	var srcOk string
	var actionOk string
	var logprefixOk string
	ma := gress.(map[string]interface{})
	switch way {
	case wayIngress:
		if (ma["from_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with ingress port source : %s", ma["from_port"].(string))
		}
		if (ma["to_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with ingress port destination : %s", ma["to_port"].(string))
		}
		if (ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "ipv6-icmp") {
			return fmt.Errorf("protocol != icmp with icmptype")
		}
		matched := strings.Contains(onCIDR, "/")
		if matched {
			dstOk = onCIDR
		} else {
			dstOk = strings.Join([]string{onCIDR, "/128"}, "")
		}
		matched = strings.Contains(ma["cidr_blocks"].(string), "/")
		if matched {
			srcOk = ma["cidr_blocks"].(string)
		} else {
			srcOk = strings.Join([]string{ma["cidr_blocks"].(string), "/128"}, "")
		}
	case wayEgress:
		if (ma["from_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with egress port source : %s", ma["from_port"].(string))
		}
		if (ma["to_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with egress port destination : %s", ma["to_port"].(string))
		}
		if (ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "ipv6-icmp") {
			return fmt.Errorf("protocol != icmp with icmptype")
		}
		matched := strings.Contains(ma["cidr_blocks"].(string), "/")
		if matched {
			dstOk = ma["cidr_blocks"].(string)
		} else {
			dstOk = strings.Join([]string{ma["cidr_blocks"].(string), "/128"}, "")
		}
		matched = strings.Contains(onCIDR, "/")
		if matched {
			srcOk = onCIDR
		} else {
			srcOk = strings.Join([]string{onCIDR, "/128"}, "")
		}
	}
	if strings.Contains(ma["action"].(string), "LOG --log-prefix") {
		actionSplit := strings.Split(ma["action"].(string), " ")
		if len(actionSplit) != numWordForLogPrefix {
			return fmt.Errorf("too many words with log-prefix : one only")
		}
		actionOk = actionSplit[0]
		logprefixOk = actionSplit[2]
	} else {
		actionOk = ma["action"].(string)
		logprefixOk = ""
	}
	rule := Rule{
		Action:    actionOk,
		State:     ma["state"].(string),
		Icmptype:  ma["icmptype"].(string),
		Fragment:  ma["fragment"].(bool),
		Chain:     d.Get("project").(string),
		Proto:     ma["protocol"].(string),
		IfaceIn:   ma["iface_in"].(string),
		IfaceOut:  ma["iface_out"].(string),
		IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
		IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
		Sports:    ma["from_port"].(string),
		Dports:    ma["to_port"].(string),
		Position:  ma["position"].(string),
		Logprefix: logprefixOk,
	}
	ruleNoPos := Rule{
		Action:    actionOk,
		State:     ma["state"].(string),
		Icmptype:  ma["icmptype"].(string),
		Fragment:  ma["fragment"].(bool),
		Chain:     d.Get("project").(string),
		Proto:     ma["protocol"].(string),
		IfaceIn:   ma["iface_in"].(string),
		IfaceOut:  ma["iface_out"].(string),
		IPSrc:     strings.ReplaceAll(srcOk, "/", "_"),
		IPDst:     strings.ReplaceAll(dstOk, "/", "_"),
		Sports:    ma["from_port"].(string),
		Dports:    ma["to_port"].(string),
		Position:  "?",
		Logprefix: logprefixOk,
	}

	switch method {
	case httpDel:
		ruleexistsNoPos, err := client.rulesAPIV6(ruleNoPos, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, ruleNoPos, err)
		}
		if ruleexistsNoPos {
			ret, err := client.rulesAPIV6(ruleNoPos, httpDel)
			if !ret || err != nil {
				return fmt.Errorf("delete rules %s %v failed : %s", onCIDR, ruleNoPos, err)
			}
		}
	case httpPut:
		ruleexists, err := client.rulesAPIV6(rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, rule, err)
		}
		if !ruleexists {
			if ma["position"].(string) != "?" {
				ruleexistsNoPos, err := client.rulesAPIV6(ruleNoPos, httpGet)
				if err != nil {
					return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, ruleNoPos, err)
				}
				if ruleexistsNoPos {
					ret, err := client.rulesAPIV6(ruleNoPos, httpDel)
					if !ret || err != nil {
						return fmt.Errorf("delete rules with bad position %s %v failed : %s", onCIDR, ruleNoPos, err)
					}
					ret, err = client.rulesAPIV6(rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
					}
				} else {
					ret, err := client.rulesAPIV6(rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
					}
				}
			} else {
				ret, err := client.rulesAPIV6(rule, httpPut)
				if !ret || err != nil {
					return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
				}
			}
		}
	case httpGet:
		ruleexists, err := client.rulesAPIV6(rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, rule, err)
		}
		if !ruleexists {
			ruleexistsNoPos, err := client.rulesAPIV6(ruleNoPos, httpGet)
			if err != nil {
				return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, ruleNoPos, err)
			}
			if ruleexistsNoPos {
				return fmt.Errorf(noExistsNoPosErr)
			}

			return fmt.Errorf(noExists)
		}
	}

	return nil
}
