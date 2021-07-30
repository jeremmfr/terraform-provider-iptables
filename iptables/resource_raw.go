package iptables

import (
	"context"
	"fmt"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func resourceRaw() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceRawCreate,
		ReadContext:   resourceRawRead,
		UpdateContext: resourceRawUpdate,
		DeleteContext: resourceRawDelete,
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
							Type:             schema.TypeString,
							Optional:         true,
							StateFunc:        protocolStateFunc,
							Default:          "0.0.0.0/0",
							ValidateDiagFunc: validateCIDRNetworkOrHostV4(),
						},
						"dst_cidr_blocks": {
							Type:             schema.TypeString,
							Optional:         true,
							StateFunc:        protocolStateFunc,
							Default:          "0.0.0.0/0",
							ValidateDiagFunc: validateCIDRNetworkOrHostV4(),
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

func resourceRawCreate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if diags := resourceRawUpdate(ctx, d, m); len(diags) > 0 {
		return diags
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceRawRead(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	if d.HasChange("rule") {
		oraw, _ := d.GetChange("rule")
		osraw := oraw.(*schema.Set)
		rawList, err := rawRule(ctx, osraw.List(), httpGet, m)
		if err != nil {
			return diag.FromErr(err)
		}
		tfErr := d.Set("rule", rawList)
		if tfErr != nil {
			panic(tfErr)
		}
	} else {
		raw := d.Get("rule")
		sraw := raw.(*schema.Set)
		rawList, err := rawRule(ctx, sraw.List(), httpGet, m)
		if err != nil {
			return diag.FromErr(err)
		}
		tfErr := d.Set("rule", rawList)
		if tfErr != nil {
			panic(tfErr)
		}
	}

	return nil
}

func resourceRawUpdate(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
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
		_, err := rawRule(ctx, oldRuleSetRemove, httpDel, m)
		if err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
		_, err = rawRule(ctx, newRuleSet.List(), httpPut, m)
		if err != nil {
			d.SetId("")

			return diag.FromErr(err)
		}
	}
	client := m.(*Client)
	if err := client.saveV4(ctx); err != nil {
		return diag.FromErr(fmt.Errorf("iptables save failed : %s", err))
	}

	return nil
}

func resourceRawDelete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	rule := d.Get("rule")
	ruleSet := rule.(*schema.Set)
	_, err := rawRule(ctx, ruleSet.List(), httpDel, m)
	if err != nil {
		return diag.FromErr(err)
	}
	client := m.(*Client)
	err = client.saveV4(ctx)
	if err != nil {
		return diag.FromErr(fmt.Errorf("iptables save failed : %s", err))
	}

	return nil
}

func rawRule(ctx context.Context, ruleList []interface{}, method string, m interface{}) ([]interface{}, error) {
	client := m.(*Client)

	var ruleListReturn []interface{}
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
			ruleexistsNoPos, err := client.rawAPIV4(ctx, ruleNoPos, httpGet)
			if err != nil {
				return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if ruleexistsNoPos {
				ret, err := client.rawAPIV4(ctx, ruleNoPos, httpDel)
				if !ret || err != nil {
					return nil, fmt.Errorf("delete rules on raw %s failed : %s", ma, err)
				}
			}
		case httpPut:
			ruleexists, err := client.rawAPIV4(ctx, rule, httpGet)
			if err != nil {
				return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if !ruleexists {
				if ma["position"].(string) != "?" {
					ruleexistsNoPos, err := client.rawAPIV4(ctx, ruleNoPos, httpGet)
					if err != nil {
						return nil, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
					}
					if ruleexistsNoPos {
						ret, err := client.rawAPIV4(ctx, ruleNoPos, httpDel)
						if !ret || err != nil {
							return nil, fmt.Errorf("delete rules with bad position on raw %s failed : %s", ma, err)
						}
						ret, err = client.rawAPIV4(ctx, rule, httpPut)
						if !ret || err != nil {
							return nil, fmt.Errorf("add rules on raw %s failed : %s", ma, err)
						}
					} else {
						ret, err := client.rawAPIV4(ctx, rule, httpPut)
						if !ret || err != nil {
							return nil, fmt.Errorf("add rules on raw %s failed %s", ma, err)
						}
					}
				} else {
					ret, err := client.rawAPIV4(ctx, rule, httpPut)
					if !ret || err != nil {
						return nil, fmt.Errorf("add rules on raw %s failed : %s", ma, err)
					}
				}
			}
		case httpGet:
			ruleexists, err := client.rawAPIV4(ctx, rule, httpGet)
			if err != nil {
				return ruleListReturn, fmt.Errorf("check rules on raw for %s failed : %s", ma, err)
			}
			if ruleexists {
				ruleListReturn = append(ruleListReturn, ma)
			} else {
				ruleexistsNoPos, err := client.rawAPIV4(ctx, ruleNoPos, httpGet)
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
