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
	"bytes"
	"sort"
	"unicode"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceRules() *schema.Resource {
	return &schema.Resource{
		Create: resourceRulesCreate,
		Read:   resourceRulesRead,
		Update:	resourceRulesUpdate,
		Delete:	resourceRulesDelete,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:       schema.TypeString,
				Required:	true,
			},
			"project": &schema.Schema{
				Type:		schema.TypeString,
				Required:	true,
			},
			"on_cidr_blocks": &schema.Schema{
				Type:       schema.TypeList,
				Required:	true,
				Elem:       &schema.Schema{Type: schema.TypeString},
			},
			"ingress": &schema.Schema{
				Type: schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
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
						"protocol": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	protocolStateFunc,
							Default:	"all",
						},
						"cidr_blocks": &schema.Schema{
							Type:		schema.TypeList,
							Optional:	true,
							Elem:		&schema.Schema{Type: schema.TypeString},
						},
						"iface_out": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	ifaceStateFunc,
							Default:    "*",
						},
						"iface_in":	&schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	ifaceStateFunc,
							Default:    "*",
						},
						"state": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"",
						},
						"icmptype": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"",
						},
						"fragment": &schema.Schema{
							Type:		schema.TypeBool,
							Optional:	true,
							Default:	false,
						},
						"action": &schema.Schema{
							Type:       schema.TypeString,
							Optional:	true,
							Default:	"ACCEPT",
						},
						"position": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"?",
						},
					},
				},
				Set: ruleHash,
			},
			"egress": &schema.Schema{
				Type: schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"from_port": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"0",
						},
						"to_port": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	0,
						},
						"protocol": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							StateFunc:	protocolStateFunc,
							Default:	"all",
						},
						"cidr_blocks": &schema.Schema{
							Type:		schema.TypeList,
							Optional:	true,
							Elem:		&schema.Schema{Type: schema.TypeString},
						},
						"iface_out": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:    "*",
						},
						"iface_in":	&schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:    "*",
						},
						"state": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"",
						},
						"icmptype": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"",
						},
						"fragment": &schema.Schema{
							Type:		schema.TypeBool,
							Optional:	true,
							Default:	false,
						},
						"action": &schema.Schema{
							Type:       schema.TypeString,
							Optional:	true,
							Default:    "ACCEPT",
						},
						"position": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"?",
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

    checkProcject, err := client.ChainAPI(d.Get("project").(string),"GET")
    if err != nil {
        return fmt.Errorf("Failed check project %s", d.Get("project"))
    }
    if !checkProcject {
		return fmt.Errorf("Failed unknown project %s", d.Get("project"))
	}
	err = resourceRulesUpdate(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!" )
	return nil
}

func resourceRulesRead(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("project") {
		o, _ := d.GetChange("project")
		if o != "" {
			d.Set("project", o)
			return fmt.Errorf("[ERROR] you can't change project")
		}
	}

	if d.HasChange("on_cidr_blocks") {
		old_on, _ := d.GetChange("on_cidr_blocks")
		rules_read_oncidr(old_on.([]interface{}), d, m)
	} else {
		on_cidr_blocks := d.Get("on_cidr_blocks")
		rules_read_oncidr(on_cidr_blocks.([]interface{}), d, m)
	}
	ingress_schema := d.Get("ingress").(*schema.Set)
	egress_schema := d.Get("egress").(*schema.Set)
	if ( len(ingress_schema.List()) == 0 ) && ( len(egress_schema.List()) == 0 ) {
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
			d.Set("project", o)
			return fmt.Errorf("[ERROR] you can't change project")
		}
	}

	if d.HasChange("on_cidr_blocks") {
		old_on, new_on := d.GetChange("on_cidr_blocks")
		on_cidr_blocks_add, on_cidr_blocks_remove := calcAddRemove(old_on.([]interface{}), new_on.([]interface{}))
		
		err := rules_remove_oncidr(on_cidr_blocks_remove, d, m)
		if err != nil {
			d.Set("on_cidr_blocks", old_on)
			return err
		}

		err = rules_add_oncidr(on_cidr_blocks_add, d, m)
		if err != nil {
			d.Set("on_cidr_blocks", old_on)
			return err
		}
	} else {
		err := rules_add_oncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
        if err != nil {
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

func resourceRulesDelete(d *schema.ResourceData, m interface{}) error {
	err := rules_remove_oncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
	if err != nil {
		d.SetId(d.Get("name").(string) + "!" )
		return err
	}
	client := m.(*Client)
	err = client.save()
	if err != nil {
		return fmt.Errorf("Failed iptables save")
	}
	return nil
}

func ruleHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["from_port"].(string)))
	buf.WriteString(fmt.Sprintf("%d-", m["to_port"].(string)))
	p := protocolForValue(m["protocol"].(string))
	buf.WriteString(fmt.Sprintf("%s-", p))
	buf.WriteString(fmt.Sprintf("%s-", m["iface_out"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["iface_in"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["state"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["icmptype"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["fragment"].(bool)))
	buf.WriteString(fmt.Sprintf("%s-", m["action"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["position"].(string)))

	if v, ok := m["cidr_blocks"]; ok {
        vs := v.([]interface{})
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

func rules_read_oncidr(on_cidr_list [] interface{}, d *schema.ResourceData, m interface{}) {
	for _, cidr := range on_cidr_list {
		if d.HasChange("ingress") {
			o, _ := d.GetChange("ingress")
			os := o.(*schema.Set)
			old_expand := expand_gress(os.List())
			err := gress_command(cidr.(string), old_expand, "in", "GET", d, m)
			if err != nil {
				d.Set("ingress", nil)
			}
			
			
		} else {
			ingr := d.Get("ingress")
			ingr_s := ingr.(*schema.Set)
			ingr_expand := expand_gress(ingr_s.List())
			err := gress_command(cidr.(string), ingr_expand, "in", "GET", d, m)
			if err != nil {
				d.Set("ingress", nil)
			}
		}
		if d.HasChange("egress") {
			o, _ := d.GetChange("egress")
			os := o.(*schema.Set)
			old_expand := expand_gress(os.List())
			err := gress_command(cidr.(string), old_expand, "out", "GET", d, m)
			if err != nil {
				d.Set("egress", nil)
			}

		} else {
			egr := d.Get("egress")
			egr_s := egr.(*schema.Set)
			egr_expand := expand_gress(egr_s.List())
			err := gress_command(cidr.(string), egr_expand, "out", "GET", d, m)
			if err != nil {
				d.Set("egress", nil)
			}
		}
	}
	return
}

func rules_remove_oncidr(on_cidr_list [] interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range on_cidr_list {
		if d.HasChange("ingress") {
			o, _ := d.GetChange("ingress")
			os := o.(*schema.Set)
			old_expand := expand_gress(os.List())
			err := gress_command(cidr.(string), old_expand, "in", "DELETE", d, m)
			if err != nil {
				d.Set("ingress", o)
				return err
			}
		} else {
			ingr := d.Get("ingress")
			ingr_s := ingr.(*schema.Set)
			ingr_expand := expand_gress(ingr_s.List())
			err := gress_command(cidr.(string), ingr_expand, "in", "DELETE", d, m)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			o, _ := d.GetChange("egress")
			os := o.(*schema.Set)
			old_expand := expand_gress(os.List())
			err := gress_command(cidr.(string), old_expand, "out", "DELETE", d, m)
			if err != nil {
				d.Set("egress", o)
				return err
			}
		} else {
			egr := d.Get("egress")
			egr_s := egr.(*schema.Set)
			egr_expand := expand_gress(egr_s.List())
			err := gress_command(cidr.(string), egr_expand, "out", "DELETE", d, m)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func rules_add_oncidr(on_cidr_list []interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range on_cidr_list {
		if d.HasChange("ingress") {
			o, n := d.GetChange("ingress")
			os := o.(*schema.Set)
			ns := n.(*schema.Set)
			os_diff := os.Difference(ns)
			ns_diff := ns.Difference(os)

//			Expand for cidr_blocks slices -> string
			os_diff_expand := expand_gress(os_diff.List())
			ns_diff_expand := expand_gress(ns_diff.List())
			ns_expand := expand_gress(ns.List())

//			calce list of remove gress
			old_remove := calcOutSlicesOfMap(os_diff_expand, ns_diff_expand)

			err := gress_command(cidr.(string), ns_expand, "in", "PUT", d, m)
			if err != nil {
				d.Set("ingress", o)
				return err
			}
			err = gress_command(cidr.(string), old_remove, "in", "DELETE", d, m)
			if err != nil {
				d.Set("ingress", o)
                return err
            }
			
		} else {
			ingr := d.Get("ingress")
			ingr_s := ingr.(*schema.Set)
//			Expand for cidr_blocks slices -> string
			ingr_expand := expand_gress(ingr_s.List())
			err := gress_command(cidr.(string), ingr_expand, "in", "PUT", d, m)
			if err != nil {
				return err
			}
		}
		if d.HasChange("egress") {
			o, n := d.GetChange("egress")
			os := o.(*schema.Set)
			ns := n.(*schema.Set)
			os_diff := os.Difference(ns)
			ns_diff := ns.Difference(os)

//			Expand for cidr_blocks slices -> string
			os_diff_expand := expand_gress(os_diff.List())
			ns_diff_expand := expand_gress(ns_diff.List())
			ns_expand := expand_gress(ns.List())

//			calce list of remove gress
			old_remove := calcOutSlicesOfMap(os_diff_expand, ns_diff_expand)
			
			err := gress_command(cidr.(string), ns_expand, "out", "PUT", d, m)
			if err != nil {
				d.Set("egress", o)
				return err
			}
			err = gress_command(cidr.(string), old_remove, "out", "DELETE", d, m)
			if err != nil {
				d.Set("egress", o)
				return err
			}
		} else {
			egr := d.Get("egress")
			egr_s := egr.(*schema.Set)
//			Expand for cidr_blocks slices -> string
			egr_expand := expand_gress(egr_s.List())
			err := gress_command(cidr.(string), egr_expand, "out", "PUT", d, m)
			if err != nil {
				return err
		    }
		}
	}
	return nil
}

func gress_command(on_cidr string, gress_list []interface{}, way string, method string, d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	for _, gress := range gress_list {
		ma := gress.(map[string]interface{})
		var dst_ok string
		var src_ok string
		var action_ok string
		var logprefix_ok string

		switch {
			case way == "in" :
				if ( ma["from_port"].(string) != "0" ) && (ma["protocol"].(string) == "all" ) {
					return fmt.Errorf("[ERROR] no protocol define with ingress port source : %s", ma["from_port"].(string))
				}
				if ( ma["to_port"].(string) != "0" ) && ( ma["protocol"].(string) == "all" )  {
					return fmt.Errorf("[ERROR] no protocol define with ingress port destination : %s", ma["to_port"].(string))
				}
				if ( ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "icmp" ) {
					return fmt.Errorf("[ERROR] protocol != icmp with icmptype")
				}
				matched := strings.Contains(on_cidr, "/")
				if matched {
					dst_ok = on_cidr
				} else {
					dst_ok = strings.Join([]string{on_cidr, "/32"}, "")
				}
				matched = strings.Contains(ma["cidr_blocks"].(string), "/")
				if matched {
					src_ok = ma["cidr_blocks"].(string)
				} else {
					src_ok = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
				}
			case way == "out" :
				if ( ma["from_port"].(string) != "0" ) && (ma["protocol"].(string) == "all" ) {
					return fmt.Errorf("[ERROR] no protocol define with egress port source : %s", ma["from_port"].(string))
				}
				if ( ma["to_port"].(string) != "0" ) && ( ma["protocol"].(string) == "all" )  {
					return fmt.Errorf("[ERROR] no protocol define with egress port destination : %s", ma["to_port"].(string))
				}
				if ( ma["icmptype"].(string) != "") && (ma["protocol"].(string) != "icmp" ) {
					return fmt.Errorf("[ERROR] protocol != icmp with icmptype")
				}
				matched := strings.Contains(ma["cidr_blocks"].(string), "/")
				if matched {
					dst_ok = ma["cidr_blocks"].(string)
				} else {
					dst_ok = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
				}
				matched = strings.Contains(on_cidr, "/")
				if matched {
					src_ok = on_cidr
				} else {
					src_ok = strings.Join([]string{on_cidr, "/32"}, "")
				}
		}
		if strings.Contains(ma["action"].(string), "LOG --log-prefix") {
			f := func(c rune) bool {
				return !unicode.IsLetter(c) && !unicode.IsNumber(c)
			}
			words := strings.FieldsFunc(ma["action"].(string), f)
			if len(words) != 4 {
				return fmt.Errorf("[ERROR] too many words with log-prefix : one only")	
			}
			action_ok =	words[0]
			logprefix_ok = words[3]
		} else {
			action_ok = ma["action"].(string)
			logprefix_ok = ""
		}

		rule := Rule{
			Action:		action_ok,
			State:		ma["state"].(string),
			Icmptype:	ma["icmptype"].(string),
			Fragment:	ma["fragment"].(bool),
			Chain:		d.Get("project").(string),
			Proto:		ma["protocol"].(string),
			Iface_in:	ma["iface_in"].(string),
			Iface_out:	ma["iface_out"].(string),
			IP_src:		strings.Replace(src_ok, "/", "_", -1),
			IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
			Sports:     ma["from_port"].(string),
			Dports:		ma["to_port"].(string),
			Position:	ma["position"].(string),
			Logprefix:	logprefix_ok,
		}
		ruleNoPos := Rule{
			Action:		action_ok,
			State:		ma["state"].(string),
			Icmptype:	ma["icmptype"].(string),
			Fragment:	ma["fragment"].(bool),
			Chain:		d.Get("project").(string),
			Proto:		ma["protocol"].(string),
			Iface_in:	ma["iface_in"].(string),
			Iface_out:	ma["iface_out"].(string),
			IP_src:		strings.Replace(src_ok, "/", "_", -1),
			IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
			Sports:     ma["from_port"].(string),
			Dports:		ma["to_port"].(string),
			Position:	"?",
			Logprefix:	logprefix_ok,
		}	
		ruleexists, err := client.RulesAPI(rule, "GET")
		if err != nil {
				return fmt.Errorf("Failed check rules for %s", on_cidr, rule, err)
		}
		switch {
			case method == "DELETE" :
				if ruleexists {
					ret, err := client.RulesAPI(rule, "DELETE")
					if ( !ret || err != nil ) {
						return fmt.Errorf("Failed delete rules %s", on_cidr, rule, err)
					}
				}
			case method == "PUT" :
				if !ruleexists {
					if ma["position"].(string) != "?" {
						rulebadpos , err := client.RulesAPI(ruleNoPos, "GET")
						if err != nil {
							return fmt.Errorf("Failed check rules for %s", on_cidr, rule, err)
						}
						if rulebadpos {
							ret, err := client.RulesAPI(ruleNoPos, "DELETE")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed delete rules with bad position %s", on_cidr, ruleNoPos, err)
							}
							ret, err = client.RulesAPI(rule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules %s", on_cidr, rule, err)
							}
						} else {
							ret, err := client.RulesAPI(rule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules %s", on_cidr, rule, err)
							}
						}
					} else {
						ret, err := client.RulesAPI(rule, "PUT")
						if ( !ret || err != nil ) {
							return fmt.Errorf("Failed add rules %s", on_cidr, rule, err)
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

func expand_gress(gress []interface{}) []interface{} {
	var	new_gress []interface{}

	for _, raw := range gress {
		ma := raw.(map[string]interface{})
		length_cidr_blocks := len(ma["cidr_blocks"].([]interface{}))

		if length_cidr_blocks == 0 {
			new_cidr := make(map[string]interface{})
			new_cidr["from_port"] = ma["from_port"].(string)
			new_cidr["to_port"] = ma["to_port"].(string)
			new_cidr["protocol"] = ma["protocol"].(string)
			new_cidr["iface_in"] = ma["iface_in"].(string)
			new_cidr["iface_out"] = ma["iface_out"].(string)
			new_cidr["action"] = ma["action"].(string)
			new_cidr["state"] = ma["state"].(string)
			new_cidr["icmptype"] = ma["icmptype"].(string)
			new_cidr["fragment"] = ma["fragment"].(bool)
			new_cidr["position"] = ma["position"].(string)
			new_cidr["cidr_blocks"] = "0.0.0.0/0"

			new_gress = append(new_gress, new_cidr)
		} else {
			for _, cidr := range ma["cidr_blocks"].([]interface{}) {
				new_cidr := make(map[string]interface{})
				new_cidr["from_port"] = ma["from_port"].(string)
				new_cidr["to_port"] = ma["to_port"].(string)
				new_cidr["protocol"] = ma["protocol"].(string)
				new_cidr["iface_in"] = ma["iface_in"].(string)
				new_cidr["iface_out"] = ma["iface_out"].(string)
				new_cidr["action"] = ma["action"].(string)
				new_cidr["state"] = ma["state"].(string)
				new_cidr["icmptype"] = ma["icmptype"].(string)
				new_cidr["fragment"] = ma["fragment"].(bool)
				new_cidr["position"] = ma["position"].(string)
				new_cidr["cidr_blocks"] = cidr.(string)

				new_gress = append(new_gress, new_cidr)
			}
		}
	}
	return new_gress
}

