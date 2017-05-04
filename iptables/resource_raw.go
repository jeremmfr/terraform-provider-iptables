// Copyright 2017 Jeremy Muriel
//
// This file is part of terraform-provider-iptables.
//
// terraform-provider-iptables is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Foobar is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with terraform-provider-iptables.  If not, see <http://www.gnu.org/licenses/>.

package iptables

import (
	"fmt"
	"strings"
	"errors"
	"log"
	"unicode"

	"github.com/hashicorp/terraform/helper/schema"
)

func resourceRaw() *schema.Resource {
	return &schema.Resource{
		Create: resourceRawCreate,
		Read:	resourceRawRead,
		Update: resourceRawUpdate,
		Delete: resourceRawDelete,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:		schema.TypeString,
				Required:	true,
			},
			"rule": &schema.Schema{
				Type: schema.TypeSet,
				Required: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"chain": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"PREROUTING",
						},
						"protocol": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	protocolStateFunc,
							Default:	"all",
						},
						"from_port": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"0",
						},
						"to_port": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"0",
						},
						"src_cidr_blocks": &schema.Schema{
							Type:		schema.TypeString,
							Optional:   true,
							StateFunc:  protocolStateFunc,
							Default:    "0.0.0.0/0",
						},
						"dst_cidr_blocks": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	protocolStateFunc,
							Default:	"0.0.0.0/0",
						},
						"iface_out": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	ifaceStateFunc,
							Default:	"*",
						},
						"iface_in": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	ifaceStateFunc,
							Default:	"*",
						},
						"action": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:    "ACCEPT",
						},
						"tcpflags_mask": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"SYN,RST,ACK,FIN",
						},
						"tcpflags_comp": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"",
						},
						"notrack": &schema.Schema{
							Type:		schema.TypeBool,
							Optional:   true,
							Default:	false,
						},
						"position": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"?",
						},
					},
				},
			},
		},
	}
}

func resourceRawCreate(d *schema.ResourceData, m interface{}) error {
	err := resourceRawUpdate(d,m)
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
		err := raw_rule(osraw.List(), "GET", d, m)
		if err != nil {
			d.SetId("")
		}
	} else {
		log.Print("no change")
		oraw := d.Get("rule")
		osraw := oraw.(*schema.Set)
		err := raw_rule(osraw.List(), "GET", d, m)
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
		old_rule, new_rule := d.GetChange("rule")
		old_rule_s := old_rule.(*schema.Set)
		new_rule_s := new_rule.(*schema.Set)
		old_rule_diff := old_rule_s.Difference(new_rule_s)
		new_rule_diff := new_rule_s.Difference(new_rule_s)
		
		old_remove := calcOutSlicesOfMap(old_rule_diff.List(), new_rule_diff.List())

		err := raw_rule(new_rule_s.List(), "PUT", d, m)
		if err != nil {
			d.Set("rule", old_rule)
			return err
		}
		err = raw_rule(old_remove, "DELETE", d, m)
		if err != nil {
			d.Set("rule", old_rule)
			return err
		}
	}
	client := m.(*Client)
	err := client.save()
	if err != nil {
		return fmt.Errorf("Failed iptables save")
	}
	return nil
}

func resourceRawDelete(d *schema.ResourceData, m interface{}) error {
	rule := d.Get("rule")
	rule_s := rule.(*schema.Set)
	err := raw_rule(rule_s.List(), "DELETE", d, m)
	if err != nil {
		return err	
	}
	client := m.(*Client)
	err = client.save()
	if err != nil {
		return fmt.Errorf("Failed iptables save")
	}
	return nil
}

func raw_rule(rule_list []interface{}, method string, d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	for _, rule := range rule_list {
		ma := rule.(map[string]interface{})
		var dst_ok string
		var src_ok string
		var action_ok string
		var logprefix_ok string

		matched := strings.Contains(ma["src_cidr_blocks"].(string), "/")
		if !matched {
			src_ok = strings.Join([]string{ma["src_cidr_blocks"].(string), "/32"}, "")
		} else {
			src_ok = ma["src_cidr_blocks"].(string)
		}
		matched = strings.Contains(ma["dst_cidr_blocks"].(string), "/")
		if !matched {
			dst_ok = strings.Join([]string{ma["dst_cidr_blocks"].(string), "/32"}, "")
		} else {
			dst_ok = ma["dst_cidr_blocks"].(string)
		}
		
		if strings.Contains(ma["action"].(string), "LOG --log-prefix") {
			f := func(c rune) bool {
				return !unicode.IsLetter(c) && !unicode.IsNumber(c)
			}
			words := strings.FieldsFunc(ma["action"].(string), f)
			if len(words) != 4 {
				return fmt.Errorf("[ERROR] too many words with log-prefix : one only")
			}
			action_ok = words[0]
			logprefix_ok = words[3]
		} else {
			action_ok = ma["action"].(string)
			logprefix_ok = ""
		}

		rule := Rule{
			Action:		action_ok,
			Chain:		ma["chain"].(string),
			Proto:		ma["protocol"].(string),
			Iface_in:	ma["iface_in"].(string),
			Iface_out:	ma["iface_out"].(string),
			IP_src:     strings.Replace(src_ok, "/", "_", -1),
			IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
			Sports:		ma["from_port"].(string),
			Dports:		ma["to_port"].(string),
			Tcpflags_1:	ma["tcpflags_mask"].(string),
			Tcpflags_2: ma["tcpflags_comp"].(string),
			Notrack:	ma["notrack"].(bool),
			Position:	ma["position"].(string),
			Logprefix:	logprefix_ok,
		}
		ruleNoPos := Rule{
			Action:		action_ok,
			Chain:		ma["chain"].(string),
			Proto:		ma["protocol"].(string),
			Iface_in:	ma["iface_in"].(string),
			Iface_out:	ma["iface_out"].(string),
			IP_src:     strings.Replace(src_ok, "/", "_", -1),
			IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
			Sports:		ma["from_port"].(string),
			Dports:		ma["to_port"].(string),
			Tcpflags_1:	ma["tcpflags_mask"].(string),
			Tcpflags_2: ma["tcpflags_comp"].(string),
			Notrack:	ma["notrack"].(bool),
			Position:	"?",
			Logprefix:	logprefix_ok,
		}	
		ruleexists, err := client.RawAPI(rule,"GET")
		if err != nil {
			return fmt.Errorf("Failed check rules on raw for %s", ma)
		}
		switch {
			case method == "DELETE" :
				if ruleexists {
					ret, err := client.RawAPI(rule, "DELETE")
					if ( !ret || err != nil ) {
						return fmt.Errorf("Failed delete rules on raw %s", ma)
					}
				}
			case method == "PUT" :
				if !ruleexists {
					if ma["position"].(string) != "?" {
						rulebadpos , err := client.RawAPI(ruleNoPos,"GET")
						if err != nil {
							return fmt.Errorf("Failed check rules on raw for %s", ma)
						}
						if rulebadpos {
							ret, err := client.RawAPI(ruleNoPos, "DELETE")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed delete rules with bad position on raw %s", ma)
							}
							ret, err = client.RawAPI(rule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules on raw %s", ma)
							}
						} else {
							ret, err := client.RawAPI(rule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules on raw %s", ma)
							}
						}
					} else {
						ret, err := client.RawAPI(rule, "PUT")
						if ( !ret || err != nil ) {
							return fmt.Errorf("Failed add rules on raw %s", ma)
						}
					}
				}
			case method == "GET" :
				if !ruleexists {
					return errors.New("No_exist")
				}
		}
    }
	return nil
}
