package iptables

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRulesIPv6() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRulesIPv6Create,
		ReadContext:   resourceRulesIPv6Read,
		UpdateContext: resourceRulesIPv6Update,
		DeleteContext: resourceRulesIPv6Delete,
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

func resourceRulesIPv6Create(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)
	if !client.IPv6 {
		return diag.FromErr(fmt.Errorf("ipv6 not enable on provider"))
	}

	checkProcject, err := client.chainAPIV6(ctx, d.Get("project").(string), httpGet)
	if err != nil {
		return diag.FromErr(fmt.Errorf("check project %s failed : %w", d.Get("project"), err))
	}
	if !checkProcject {
		return diag.FromErr(fmt.Errorf("unknown project %s", d.Get("project")))
	}
	if diags := resourceRulesIPv6Update(ctx, d, m); len(diags) > 0 {
		return diags
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceRulesIPv6Read(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("project") {
		o, _ := d.GetChange("project")
		if o != "" {
			if tfErr := d.Set("project", o); tfErr != nil {
				panic(tfErr)
			}

			return diag.FromErr(fmt.Errorf("you can't change project"))
		}
	}

	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, _ := d.GetChange("on_cidr_blocks")
		if err := rulesReadOnCIDRV6(ctx, oldOnCIDR.(*schema.Set).List(), d, m); err != nil {
			return diag.FromErr(err)
		}
	} else {
		if err := rulesReadOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m); err != nil {
			return diag.FromErr(err)
		}
	}
	if (len(d.Get("ingress").(*schema.Set).List()) == 0) && (len(d.Get("egress").(*schema.Set).List()) == 0) {
		d.SetId("")
	}

	return nil
}

func resourceRulesIPv6Update(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			d.SetId(n.(string) + "!")
		}
	}

	if err := checkRulesPositionAndCIDRList(d); err != nil {
		d.SetId("")

		return diag.FromErr(err)
	}
	if d.HasChange("project") {
		o, _ := d.GetChange("project")
		if o != "" {
			d.SetId("")

			return diag.FromErr(fmt.Errorf("you can't change project"))
		}
	}

	if d.HasChange("on_cidr_blocks") {
		oldOnCIDR, newOnCIDR := d.GetChange("on_cidr_blocks")
		onCIDRRemove := computeRemove(oldOnCIDR.(*schema.Set).List(), newOnCIDR.(*schema.Set).List())
		if err := rulesRemoveOnCIDRV6(ctx, onCIDRRemove, d, m); err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
		if err := rulesAddOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m); err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
	} else {
		if err := rulesAddOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m); err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
	}
	client := m.(*Client)
	if err := client.saveV6(ctx); err != nil {
		return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
	}

	return nil
}

func resourceRulesIPv6Delete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if err := rulesRemoveOnCIDRV6(ctx, d.Get("on_cidr_blocks").(*schema.Set).List(), d, m); err != nil {
		d.SetId(d.Get("name").(string) + "!")

		return diag.FromErr(err)
	}
	client := m.(*Client)
	if err := client.saveV6(ctx); err != nil {
		return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
	}

	return nil
}

func rulesReadOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	project := d.Get("project").(string)
	ingress := d.Get("ingress").(*schema.Set).List()
	if d.HasChange("ingress") {
		oldIngress, _ := d.GetChange("ingress")
		ingress = oldIngress.(*schema.Set).List()
	}
	egress := d.Get("egress").(*schema.Set).List()
	if d.HasChange("egress") {
		oldEgress, _ := d.GetChange("egress")
		egress = oldEgress.(*schema.Set).List()
	}
	for _, cidr := range onCIDRList {
		// ingress
		ingressRead, err := gressListCommandV6(ctx, cidr.(string), ingress, wayIngress, httpGet, project, m, false)
		if err != nil {
			return err
		}
		ingress = make([]interface{}, len(ingressRead))
		copy(ingress, ingressRead)
		if tfErr := d.Set("ingress", ingressRead); tfErr != nil {
			panic(tfErr)
		}
		// egress
		egressRead, err := gressListCommandV6(ctx, cidr.(string), egress, wayEgress, httpGet, project, m, false)
		if err != nil {
			return err
		}
		egress = make([]interface{}, len(egressRead))
		copy(egress, egressRead)
		if tfErr := d.Set("egress", egressRead); tfErr != nil {
			panic(tfErr)
		}
	}

	return nil
}

func rulesRemoveOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	project := d.Get("project").(string)
	for _, cidr := range onCIDRList {
		if d.HasChange("ingress") {
			oldIngress, _ := d.GetChange("ingress")
			if _, err := gressListCommandV6(
				ctx, cidr.(string), oldIngress.(*schema.Set).List(), wayIngress, httpDel, project, m, false); err != nil {
				return err
			}
		} else {
			if _, err := gressListCommandV6(
				ctx, cidr.(string), d.Get("ingress").(*schema.Set).List(), wayIngress, httpDel, project, m, false); err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			oldEgress, _ := d.GetChange("egress")
			if _, err := gressListCommandV6(
				ctx, cidr.(string), oldEgress.(*schema.Set).List(), wayEgress, httpDel, project, m, false); err != nil {
				return err
			}
		} else {
			if _, err := gressListCommandV6(
				ctx, cidr.(string), d.Get("egress").(*schema.Set).List(), wayEgress, httpDel, project, m, false); err != nil {
				return err
			}
		}
	}

	return nil
}

func rulesAddOnCIDRV6(ctx context.Context, onCIDRList []interface{}, d *schema.ResourceData, m interface{}) error {
	project := d.Get("project").(string)
	for _, cidr := range onCIDRList {
		if err := checkCIDRBlocksString(cidr.(string), ipv6ver); err != nil {
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

			if _, err := gressListCommandV6(
				ctx, cidr.(string), oldIngressSetExpandedRemove, wayIngress, httpDel, project, m, true); err != nil {
				return err
			}
			if _, err := gressListCommandV6(
				ctx, cidr.(string), newIngress.(*schema.Set).List(), wayIngress, httpPut, project, m, false); err != nil {
				return err
			}
		} else {
			if _, err := gressListCommandV6(
				ctx, cidr.(string), d.Get("ingress").(*schema.Set).List(), wayIngress, httpPut, project, m, false); err != nil {
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

			if _, err := gressListCommandV6(
				ctx, cidr.(string), oldEgressSetExpandedRemove, wayEgress, httpDel, project, m, true); err != nil {
				return err
			}
			if _, err := gressListCommandV6(
				ctx, cidr.(string), newEgress.(*schema.Set).List(), wayEgress, httpPut, project, m, false); err != nil {
				return err
			}
		} else {
			if _, err := gressListCommandV6(
				ctx, cidr.(string), d.Get("egress").(*schema.Set).List(), wayEgress, httpPut, project, m, false); err != nil {
				return err
			}
		}
	}

	return nil
}

func gressListCommandV6(
	ctx context.Context,
	onCIDR string,
	gressList []interface{},
	way, method, project string,
	m interface{},
	cidrExpanded bool,
) ([]interface{}, error) {
	switch method {
	case httpGet:
		if cidrExpanded {
			return nil, fmt.Errorf("internal error : gressListCommand Get with cidrExpanded")
		}
		var saves []interface{}
		for _, gressElement := range gressList {
			gressOK := true
			gressOKnoPos := false
			gressExpand := expandCIDRInGress(gressElement, ipv6ver)
			for _, gressExpandElement := range gressExpand {
				if err := gressCmdV6(ctx, onCIDR, gressExpandElement, way, httpGet, project, m); err != nil {
					if !strings.Contains(err.Error(), noExists) {
						return nil, err
					}
					gressOK = false
					if err.Error() == noExistsNoPosErr {
						gressOKnoPos = true
					}
				}
			}
			if gressOK {
				saves = append(saves, gressElement)
			}
			if gressOKnoPos {
				gressElement.(map[string]interface{})["position"] = "?"
				saves = append(saves, gressElement)
			}
		}

		return saves, nil
	case httpDel:
		if cidrExpanded {
			for _, gressElement := range gressList {
				if err := gressCmdV6(ctx, onCIDR, gressElement, way, httpDel, project, m); err != nil {
					return nil, err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv6ver)
				for _, gressExpandElement := range gressExpand {
					if err := gressCmdV6(ctx, onCIDR, gressExpandElement, way, httpDel, project, m); err != nil {
						return nil, err
					}
				}
			}
		}

		return nil, nil
	case httpPut:
		if cidrExpanded {
			for _, gressElement := range gressList {
				if err := checkCIDRBlocksInMap(gressElement.(map[string]interface{}), ipv6ver); err != nil {
					return nil, err
				}
				if err := gressCmdV6(ctx, onCIDR, gressElement, way, httpPut, project, m); err != nil {
					return nil, err
				}
			}
		} else {
			for _, gressElement := range gressList {
				gressExpand := expandCIDRInGress(gressElement, ipv6ver)
				for _, gressExpandElement := range gressExpand {
					if err := checkCIDRBlocksInMap(gressExpandElement.(map[string]interface{}), ipv6ver); err != nil {
						return nil, err
					}
					if err := gressCmdV6(ctx, onCIDR, gressExpandElement, way, httpPut, project, m); err != nil {
						return nil, err
					}
				}
			}
		}

		return nil, nil
	}

	return nil, fmt.Errorf("internal error : unknown method for gressListCommand")
}

func gressCmdV6(
	ctx context.Context, onCIDR string, gress interface{}, way, method, project string, m interface{},
) error {
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
		Chain:     project,
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
		Chain:     project,
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
		ruleexistsNoPos, err := client.rulesAPIV6(ctx, ruleNoPos, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %w", onCIDR, ruleNoPos, err)
		}
		if ruleexistsNoPos {
			ret, err := client.rulesAPIV6(ctx, ruleNoPos, httpDel)
			if !ret || err != nil {
				return fmt.Errorf("delete rules %s %v failed : %w", onCIDR, ruleNoPos, err)
			}
		}
	case httpPut:
		ruleexists, err := client.rulesAPIV6(ctx, rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %w", onCIDR, rule, err)
		}
		if !ruleexists {
			if ma["position"].(string) != "?" {
				ruleexistsNoPos, err := client.rulesAPIV6(ctx, ruleNoPos, httpGet)
				if err != nil {
					return fmt.Errorf("check rules exists for %s %v failed : %w", onCIDR, ruleNoPos, err)
				}
				if ruleexistsNoPos {
					ret, err := client.rulesAPIV6(ctx, ruleNoPos, httpDel)
					if !ret || err != nil {
						return fmt.Errorf("delete rules with bad position %s %v failed : %w", onCIDR, ruleNoPos, err)
					}
					ret, err = client.rulesAPIV6(ctx, rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %w", onCIDR, rule, err)
					}
				} else {
					ret, err := client.rulesAPIV6(ctx, rule, httpPut)
					if !ret || err != nil {
						return fmt.Errorf("add rules %s %v failed : %w", onCIDR, rule, err)
					}
				}
			} else {
				ret, err := client.rulesAPIV6(ctx, rule, httpPut)
				if !ret || err != nil {
					return fmt.Errorf("add rules %s %v failed : %w", onCIDR, rule, err)
				}
			}
		}
	case httpGet:
		ruleexists, err := client.rulesAPIV6(ctx, rule, httpGet)
		if err != nil {
			return fmt.Errorf("check rules exists for %s %v failed : %w", onCIDR, rule, err)
		}
		if !ruleexists {
			ruleexistsNoPos, err := client.rulesAPIV6(ctx, ruleNoPos, httpGet)
			if err != nil {
				return fmt.Errorf("check rules exists for %s %v failed : %w", onCIDR, ruleNoPos, err)
			}
			if ruleexistsNoPos {
				return fmt.Errorf(noExistsNoPosErr)
			}

			return fmt.Errorf(noExists)
		}
	}

	return nil
}
