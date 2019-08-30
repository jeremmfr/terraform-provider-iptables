package iptables

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	"github.com/hashicorp/terraform/helper/schema"
)

func resourceRules() *schema.Resource {
	return &schema.Resource{
		Create: resourceRulesCreate,
		Read:   resourceRulesRead,
		Update: resourceRulesUpdate,
		Delete: resourceRulesDelete,
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
				Type:     schema.TypeList,
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
								if listlen > 15 {
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
								if listlen > 15 {
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
							Type:     schema.TypeList,
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
								if listlen > 15 {
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
								if listlen > 15 {
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
							Type:     schema.TypeList,
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

func resourceRulesCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	checkProcject, err := client.chainAPIV4(d.Get("project").(string), httpGet)
	if err != nil {
		return fmt.Errorf("failed check project %s : %s", d.Get("project"), err)
	}
	if !checkProcject {
		return fmt.Errorf("failed unknown project %s", d.Get("project"))
	}
	err = resourceRulesUpdate(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!")
	return nil
}

func resourceRulesRead(d *schema.ResourceData, m interface{}) error {
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
		rulesReadOnCIDR(oldOnCIDR.([]interface{}), d, m)
	} else {
		onCIDR := d.Get("on_cidr_blocks")
		rulesReadOnCIDR(onCIDR.([]interface{}), d, m)
	}
	ingressSet := d.Get("ingress").(*schema.Set)
	egressSet := d.Get("egress").(*schema.Set)
	if (len(ingressSet.List()) == 0) && (len(egressSet.List()) == 0) {
		d.SetId("")
	}
	return nil
}

func resourceRulesUpdate(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}
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
		oldOnCIDR, newOnCIDR := d.GetChange("on_cidr_blocks")
		_, onCIDRRemove := computeAddRemove(oldOnCIDR.([]interface{}), newOnCIDR.([]interface{}))

		err := rulesRemoveOnCIDR(onCIDRRemove, d, m)
		if err != nil {
			return err
		}
		err = rulesAddOncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
		if err != nil {
			return err
		}
	} else {
		err := rulesAddOncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
		if err != nil {
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

func resourceRulesDelete(d *schema.ResourceData, m interface{}) error {
	err := rulesRemoveOnCIDR(d.Get("on_cidr_blocks").([]interface{}), d, m)
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

func rulesReadOnCIDR(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) {
	for _, cidr := range onCIDRList {
		if d.HasChange("ingress") {
			oldIngress, _ := d.GetChange("ingress")
			oldIngressSet := oldIngress.(*schema.Set)
			err := gressListCommand(cidr.(string), oldIngressSet.List(), wayIngress, httpGet, d, m, false)
			if err != nil {
				tfErr := d.Set("ingress", nil)
				if tfErr != nil {
					panic(tfErr)
				}
			}

		} else {
			ingress := d.Get("ingress")
			ingressSet := ingress.(*schema.Set)
			err := gressListCommand(cidr.(string), ingressSet.List(), wayIngress, httpGet, d, m, false)
			if err != nil {
				tfErr := d.Set("ingress", nil)
				if tfErr != nil {
					panic(tfErr)
				}
			}
		}
		if d.HasChange("egress") {
			oldEgress, _ := d.GetChange("egress")
			oldEgressSet := oldEgress.(*schema.Set)
			err := gressListCommand(cidr.(string), oldEgressSet.List(), wayEgress, httpGet, d, m, false)
			if err != nil {
				tfErr := d.Set("egress", nil)
				if tfErr != nil {
					panic(tfErr)
				}
			}

		} else {
			egress := d.Get("egress")
			egressSet := egress.(*schema.Set)
			err := gressListCommand(cidr.(string), egressSet.List(), wayEgress, httpGet, d, m, false)
			if err != nil {
				tfErr := d.Set("egress", nil)
				if tfErr != nil {
					panic(tfErr)
				}
			}
		}
	}
}

func rulesRemoveOnCIDR(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		if d.HasChange("ingress") {
			oldIngress, _ := d.GetChange("ingress")
			oldIngressSet := oldIngress.(*schema.Set)
			err := gressListCommand(cidr.(string), oldIngressSet.List(), wayIngress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			ingress := d.Get("ingress")
			ingressSet := ingress.(*schema.Set)
			err := gressListCommand(cidr.(string), ingressSet.List(), wayIngress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, _ := d.GetChange("egress")
			oldEgressSet := oldEgress.(*schema.Set)
			err := gressListCommand(cidr.(string), oldEgressSet.List(), wayEgress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		} else {
			egress := d.Get("egress")
			egressSet := egress.(*schema.Set)
			err := gressListCommand(cidr.(string), egressSet.List(), wayEgress, httpDel, d, m, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func rulesAddOncidr(onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range onCIDRList {
		err := checkCIDRBlocksString(cidr.(string), ipv4ver)
		if err != nil {
			return err
		}
		if d.HasChange("ingress") {
			oldIngress, newIngress := d.GetChange("ingress")
			oldIngressSet := oldIngress.(*schema.Set)
			newIngressSet := newIngress.(*schema.Set)
			oldIngressSetDiff := oldIngressSet.Difference(newIngressSet)
			newIngressSetDiff := newIngressSet.Difference(oldIngressSet)

			//			Expand for cidr_blocks slices -> string
			oldIngressSetDiffExpanded := expandCIDRInGressList(oldIngressSetDiff.List(), ipv4ver)
			newIngressSetDiffExpanded := expandCIDRInGressList(newIngressSetDiff.List(), ipv4ver)
			//			computation of expanded deleted gress list
			oldIngressSetExpandedRemove := computeOutSlicesOfMap(oldIngressSetDiffExpanded, newIngressSetDiffExpanded)

			err = gressListCommand(cidr.(string), oldIngressSetExpandedRemove, wayIngress, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err := gressListCommand(cidr.(string), newIngressSet.List(), wayIngress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			ingress := d.Get("ingress")
			ingressSet := ingress.(*schema.Set)
			err := gressListCommand(cidr.(string), ingressSet.List(), wayIngress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, newEgress := d.GetChange("egress")
			oldEgressSet := oldEgress.(*schema.Set)
			newEgressSet := newEgress.(*schema.Set)
			oldEgressSetDiff := oldEgressSet.Difference(newEgressSet)
			newEgressSetDiff := newEgressSet.Difference(oldEgressSet)

			//			Expand for cidr_blocks slices -> string
			oldEgressSetDiffExpanded := expandCIDRInGressList(oldEgressSetDiff.List(), ipv4ver)
			newEgressSetDiffExpanded := expandCIDRInGressList(newEgressSetDiff.List(), ipv4ver)
			//			computation of expanded deleted gress list
			oldEgressSetExpandedRemove := computeOutSlicesOfMap(oldEgressSetDiffExpanded, newEgressSetDiffExpanded)

			err := gressListCommand(cidr.(string), oldEgressSetExpandedRemove, wayEgress, httpDel, d, m, true)
			if err != nil {
				return err
			}
			err = gressListCommand(cidr.(string), newEgressSet.List(), wayEgress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		} else {
			egress := d.Get("egress")
			egressSet := egress.(*schema.Set)
			err := gressListCommand(cidr.(string), egressSet.List(), wayEgress, httpPut, d, m, false)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func gressListCommand(onCIDR string, gressList []interface{}, way string, method string, d *schema.ResourceData, m interface{}, cidrExpanded bool) error {
	switch method {
	case httpGet:
		if cidrExpanded {
			return fmt.Errorf("internal error : gressListCommand Get with cidrExpanded")
		}
		var saves []map[string]interface{}
		for _, gressElement := range gressList {
			gressOK := true
			gressExpand := expandCIDRInGress(gressElement, ipv4ver)
			for _, gressExpandElement := range gressExpand {
				err := gressCmd(onCIDR, gressExpandElement, way, httpGet, d, m)
				if err != nil {
					gressOK = false
				}
			}
			if gressOK {
				saves = append(saves, gressElement.(map[string]interface{}))
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
				err := gressCmd(onCIDR, gressElement, way, httpDel, d, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv4ver)
				for _, gressExpandElement := range gressExpand {
					err := gressCmd(onCIDR, gressExpandElement, way, httpDel, d, m)
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
				err := checkCIDRBlocksInMap(gressElement.(map[string]interface{}), ipv4ver)
				if err != nil {
					return err
				}
				err = gressCmd(onCIDR, gressElement, way, httpPut, d, m)
				if err != nil {
					return err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv4ver)
				for _, gressExpandElement := range gressExpand {
					err := checkCIDRBlocksInMap(gressExpandElement.(map[string]interface{}), ipv4ver)
					if err != nil {
						return err
					}
					err = gressCmd(onCIDR, gressExpandElement, way, httpPut, d, m)
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

func gressCmd(onCIDR string, gress interface{}, way string, method string, d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
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
		if (ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "icmp") {
			return fmt.Errorf("protocol != icmp with icmptype")
		}
		matched := strings.Contains(onCIDR, "/")
		if matched {
			dstOk = onCIDR
		} else {
			dstOk = strings.Join([]string{onCIDR, "/32"}, "")
		}
		matched = strings.Contains(ma["cidr_blocks"].(string), "/")
		if matched {
			srcOk = ma["cidr_blocks"].(string)
		} else {
			srcOk = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
		}
	case wayEgress:
		if (ma["from_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with egress port source : %s", ma["from_port"].(string))
		}
		if (ma["to_port"].(string) != "0") && (ma["protocol"].(string) == strAll) {
			return fmt.Errorf("no protocol define with egress port destination : %s", ma["to_port"].(string))
		}
		if (ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "icmp") {
			return fmt.Errorf("protocol != icmp with icmptype")
		}
		matched := strings.Contains(ma["cidr_blocks"].(string), "/")
		if matched {
			dstOk = ma["cidr_blocks"].(string)
		} else {
			dstOk = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
		}
		matched = strings.Contains(onCIDR, "/")
		if matched {
			srcOk = onCIDR
		} else {
			srcOk = strings.Join([]string{onCIDR, "/32"}, "")
		}
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
		State:     ma["state"].(string),
		Icmptype:  ma["icmptype"].(string),
		Fragment:  ma["fragment"].(bool),
		Chain:     d.Get("project").(string),
		Proto:     ma["protocol"].(string),
		IfaceIn:   ma["iface_in"].(string),
		IfaceOut:  ma["iface_out"].(string),
		IPSrc:     strings.Replace(srcOk, "/", "_", -1),
		IPDst:     strings.Replace(dstOk, "/", "_", -1),
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
		IPSrc:     strings.Replace(srcOk, "/", "_", -1),
		IPDst:     strings.Replace(dstOk, "/", "_", -1),
		Sports:    ma["from_port"].(string),
		Dports:    ma["to_port"].(string),
		Position:  "?",
		Logprefix: logprefixOk,
	}

	switch method {
	case httpDel:
		ruleexistsNoPos, err := client.rulesAPIV4(ruleNoPos, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, ruleNoPos, err)
		}
		if ruleexistsNoPos {
			ret, err := client.rulesAPIV4(ruleNoPos, httpDel)
			if !ret || err != nil {
				return fmt.Errorf("delete rules %s %v failed : %s", onCIDR, ruleNoPos, err)
			}
		}
	case httpPut:
		ruleexists, err := client.rulesAPIV4(rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, rule, err)
		}
		if !ruleexists {
			if ma["position"].(string) != "?" {
				ruleexistsNoPos, err := client.rulesAPIV4(ruleNoPos, httpGet)
				if err != nil {
					return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, ruleNoPos, err)
				}
				if ruleexistsNoPos {
					ret, err := client.rulesAPIV4(ruleNoPos, httpDel)
					if !ret || err != nil {
						return fmt.Errorf("delete rules with bad position %s %v failed : %s", onCIDR, ruleNoPos, err)
					}
					ret, err = client.rulesAPIV4(rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
					}
				} else {
					ret, err := client.rulesAPIV4(rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
					}
				}
			} else {
				ret, err := client.rulesAPIV4(rule, httpPut)
				if !ret || err != nil {
					return fmt.Errorf("add rules %s %v failed : %s", onCIDR, rule, err)
				}
			}
		}
	case httpGet:
		ruleexists, err := client.rulesAPIV4(rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %s", onCIDR, rule, err)
		}
		if !ruleexists {
			return errors.New("no_exist")
		}
	}
	return nil
}
