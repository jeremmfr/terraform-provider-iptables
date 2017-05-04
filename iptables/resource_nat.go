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
	"bytes"
	"sort"
	"strings"

	"github.com/hashicorp/terraform/helper/hashcode"
	"github.com/hashicorp/terraform/helper/schema"
)

func resourceNat() *schema.Resource {
	return &schema.Resource{
		Create: resourceNatCreate,
		Read:   resourceNatRead,
		Update: resourceNatUpdate,
		Delete: resourceNatDelete,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:	   schema.TypeString,
				Required:   true,
			},
			"on_cidr_blocks": &schema.Schema{
				Type:	   schema.TypeList,
				Required:   true,
				Elem:		&schema.Schema{Type: schema.TypeString},
			},
			"snat": &schema.Schema{
				Type: schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"to_port": &schema.Schema{
							Type:	   schema.TypeString,
							Optional:   true,
							Default:	"0",
						},
						"protocol": &schema.Schema{
							Type:	   schema.TypeString,
							Optional:   true,
							StateFunc:  protocolStateFunc,
							Default:	"all",
						},
						"iface": &schema.Schema{
							Type:	   schema.TypeString,
							Required:   true,
							StateFunc:  ifaceStateFunc,
						},
						"filter_cidr_blocks": &schema.Schema{
							Type:	   schema.TypeList,
							Optional:   true,
							Elem:	   &schema.Schema{Type: schema.TypeString},
						},
						"nat_ip": &schema.Schema{
							Type:	   schema.TypeString,
							Required:   true,
						},
						"nth_every": &schema.Schema{
							Type:		schema.TypeString,
							Optional:   true,
							Default:    "",
						},
						"nth_packet": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"0",
						},
						"position": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"?",
						},
					},
				},
				Set: NatHash,
			},
			"dnat": &schema.Schema{
				Type: schema.TypeSet,
				Optional: true,
				Elem: &schema.Resource{
					Schema: map[string]*schema.Schema{
						"to_port": &schema.Schema{
							Type:	   schema.TypeString,
							Optional:   true,
							Default:	"0",
						},
						"protocol": &schema.Schema{
							Type:	   schema.TypeString,
							Optional:   true,
							StateFunc:  protocolStateFunc,
							Default:	"all",
						},
						"iface": &schema.Schema{
							Type:		schema.TypeString,
							Required:   true,
							StateFunc:  ifaceStateFunc,
						},
						"filter_cidr_blocks": &schema.Schema{
							Type:	   schema.TypeList,
							Optional:   true,
							Elem:	   &schema.Schema{Type: schema.TypeString},
						},
						"nat_ip": &schema.Schema{
							Type:	   schema.TypeString,
							Required:   true,
						},
						"nth_every": &schema.Schema{
							Type:		schema.TypeString,
							Optional:   true,
							Default:    "",
						},
						"nth_packet": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"0",
						},
						"position": &schema.Schema{
							Type:		schema.TypeString,
							Optional:	true,
							Default:	"?",
						},
					},
				},
				Set: NatHash,
			},
		},
	}
}

func resourceNatCreate(d *schema.ResourceData, m interface{}) error {
	err := resourceNatUpdate(d, m)
	if err != nil {
		return err
	}
	d.SetId(d.Get("name").(string) + "!" )
	return nil
}
func resourceNatRead(d *schema.ResourceData, m interface{}) error {
	if d.HasChange("on_cidr_blocks") {
		old_on, _ := d.GetChange("on_cidr_blocks")
		nat_read_oncidr(old_on.([]interface{}), d, m)
	} else {
		on_cidr_blocks := d.Get("on_cidr_blocks")
		nat_read_oncidr(on_cidr_blocks.([]interface{}), d, m)
	}
	snat_schema := d.Get("snat").(*schema.Set)
	dnat_schema := d.Get("dnat").(*schema.Set)
	if ( len(snat_schema.List()) == 0 ) && ( len(dnat_schema.List()) == 0 ) {
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
	if d.HasChange("on_cidr_blocks") {
		old_on, new_on := d.GetChange("on_cidr_blocks")
		on_cidr_blocks_add, on_cidr_blocks_remove := calcAddRemove(old_on.([]interface{}), new_on.([]interface{}))		

		err := nat_remove_oncidr(on_cidr_blocks_remove, d, m)
		if err != nil {
			d.Set("on_cidr_blocks", old_on)
			return err
		}
		err = nat_add_oncidr(on_cidr_blocks_add, d, m)
		if err != nil {
			d.Set("on_cidr_blocks", old_on)
			return err
		}
	} else {
		err := nat_add_oncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
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
func resourceNatDelete(d *schema.ResourceData, m interface{}) error {
	err := nat_remove_oncidr(d.Get("on_cidr_blocks").([]interface{}), d, m)
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
						
func NatHash(v interface{}) int {
	var buf bytes.Buffer
	m := v.(map[string]interface{})
	buf.WriteString(fmt.Sprintf("%d-", m["to_port"].(string)))
	p := protocolForValue(m["protocol"].(string))
	buf.WriteString(fmt.Sprintf("%s-", p))
	buf.WriteString(fmt.Sprintf("%s-", m["nat_ip"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["iface"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["position"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["nth_every"].(string)))
	buf.WriteString(fmt.Sprintf("%s-", m["nth_packet"].(string)))

	if v, ok := m["filter_cidr_blocks"]; ok {
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

func nat_read_oncidr(on_cidr_list [] interface{}, d *schema.ResourceData, m interface{}) {
	for _, cidr := range on_cidr_list {
		if d.HasChange("snat") {
			o, _ := d.GetChange("snat")
			os := o.(*schema.Set)
			old_expand := expand_nat(os.List(), "source")
			err := nat_command(cidr.(string), old_expand, "GET", d, m)
			if err != nil {
				d.Set("snat", nil)
			}
		} else {
			nat := d.Get("snat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "source")
			err := nat_command(cidr.(string), nat_expand, "GET", d, m)
			if err != nil {
				d.Set("snat", nil)
			}
		}
		if d.HasChange("dnat") {
			o, _ := d.GetChange("dnat")
			os := o.(*schema.Set)
			old_expand := expand_nat(os.List(), "destination")
			err := nat_command(cidr.(string), old_expand, "GET", d, m)
			if err != nil {
				d.Set("dnat", nil)
			}
		} else {
			nat := d.Get("dnat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "destination")
			err := nat_command(cidr.(string), nat_expand, "GET", d, m)
			if err != nil {
				d.Set("dnat", nil)
			}
		}
	}
	return
}
func nat_remove_oncidr(on_cidr_list [] interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range on_cidr_list {
		if d.HasChange("snat") {
			o, _ := d.GetChange("snat")
			os := o.(*schema.Set)
			old_expand := expand_nat(os.List(), "source")
			err := nat_command(cidr.(string), old_expand, "DELETE", d, m)
			if err != nil {
                d.Set("snat", o)
                return err
            }

		} else {
			nat := d.Get("snat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "source")
			err := nat_command(cidr.(string), nat_expand, "DELETE", d, m)
			if err != nil {
				return err
			}
		}
		if d.HasChange("dnat") {
			o, _ := d.GetChange("dnat")
			os := o.(*schema.Set)
			old_expand := expand_nat(os.List(), "destination")
			err := nat_command(cidr.(string), old_expand, "DELETE", d, m)
			if err != nil {
                d.Set("dnat", o)
                return err
            }

		} else {
			nat := d.Get("dnat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "destination")
			err := nat_command(cidr.(string), nat_expand, "DELETE", d, m)
			if err != nil {
				return err
			}
		}
	}
	return nil
}
func nat_add_oncidr(on_cidr_list [] interface{}, d *schema.ResourceData, m interface{}) error {
	for _, cidr := range on_cidr_list {
		if d.HasChange("snat") {
			o, n := d.GetChange("snat")
			os := o.(*schema.Set)
            ns := n.(*schema.Set)
            os_diff := os.Difference(ns)
            ns_diff := ns.Difference(os)

			os_diff_expand := expand_nat(os_diff.List(), "source")
			ns_diff_expand := expand_nat(ns_diff.List(), "source")
			ns_expand := expand_nat(ns.List(), "source")

			old_remove := calcOutSlicesOfMap(os_diff_expand, ns_diff_expand)

            err := nat_command(cidr.(string), ns_expand, "PUT", d, m)
            if err != nil {
                d.Set("snat", o)
                return err
            }
			err = nat_command(cidr.(string), old_remove, "DELETE", d, m)
			if err != nil {
                d.Set("snat", o)
                return err
            }
		} else {
			nat := d.Get("snat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "source")
			err := nat_command(cidr.(string), nat_expand, "PUT", d, m)
			if err != nil {
				return err
			}
			
		}
		if d.HasChange("dnat") {
			o, n := d.GetChange("dnat")
			os := o.(*schema.Set)
            ns := n.(*schema.Set)
            os_diff := os.Difference(ns)
            ns_diff := ns.Difference(os)

			os_diff_expand := expand_nat(os_diff.List(), "destination")
			ns_diff_expand := expand_nat(ns_diff.List(), "destination")
			ns_expand := expand_nat(ns.List(), "destination")

			old_remove := calcOutSlicesOfMap(os_diff_expand, ns_diff_expand)

            err := nat_command(cidr.(string), ns_expand, "PUT", d, m)
            if err != nil {
                d.Set("dnat", o)
                return err
            }
			err = nat_command(cidr.(string), old_remove, "DELETE", d, m)
			if err != nil {
                d.Set("dnat", o)
                return err
            }
		} else {
			nat := d.Get("dnat")
			nat_s := nat.(*schema.Set)
			nat_expand := expand_nat(nat_s.List(), "destination")
			err := nat_command(cidr.(string), nat_expand, "PUT", d, m)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func expand_nat(nat []interface{}, way string) []interface{} {
	var new_nat []interface{}

	for _, raw := range nat {
		ma := raw.(map[string]interface{})
		length_filter := len(ma["filter_cidr_blocks"].([]interface{}))

		if length_filter == 0 {
			new_cidr := make(map[string]interface{})
			new_cidr["protocol"] = ma["protocol"].(string)
			new_cidr["iface"] = ma["iface"].(string)
			new_cidr["cidr_blocks"] = "0.0.0.0/0"
			new_cidr["nat_ip"] = ma["nat_ip"].(string)
			new_cidr["position"] = ma["position"].(string)
			new_cidr["to_port"] = ma["to_port"].(string)
			new_cidr["nth_every"] = ma["nth_every"].(string)
			new_cidr["nth_packet"] = ma["nth_packet"].(string)
			if way == "destination" {
				new_cidr["action"] = "dnat"
			}
			if way == "source" {
				new_cidr["action"] = "snat"
			}
			new_nat = append(new_nat, new_cidr)		
		} else {
			for _, cidr := range ma["filter_cidr_blocks"].([]interface{}) {
				new_cidr := make(map[string]interface{})
				new_cidr["protocol"] = ma["protocol"].(string)
				new_cidr["iface"] = ma["iface"].(string)
				new_cidr["cidr_blocks"] = cidr.(string)
				new_cidr["nat_ip"] = ma["nat_ip"].(string)
				new_cidr["position"] = ma["position"].(string)
				new_cidr["to_port"] = ma["to_port"].(string)
				new_cidr["nth_every"] = ma["nth_every"].(string)
				new_cidr["nth_packet"] = ma["nth_packet"].(string)
				if way == "destination" {
					new_cidr["action"] = "dnat"
				}
				if way == "source" {
					new_cidr["action"] = "snat"
				}
				new_nat = append(new_nat, new_cidr)		
			}
		}
	}
	return new_nat
}

func nat_command(on_cidr string, nat_rules []interface{}, method string, d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	for _, nat := range nat_rules {
		ma := nat.(map[string]interface{})
		var dst_ok string
        var src_ok string
		var natRule Rule
		var natRuleNoPos Rule

		if ( ma["to_port"].(string) != "0" ) && ( ma["protocol"].(string) == "all" ) {
			return fmt.Errorf("[ERROR] need protocol for to_port specification")
		}
		switch { 
			case ma["action"].(string) == "snat" :
				mask_ok := strings.Contains(on_cidr, "/")
				if mask_ok {
					src_ok = on_cidr
				} else {
					src_ok = strings.Join([]string{on_cidr, "/32"}, "")
				}
				mask_ok = strings.Contains(ma["cidr_blocks"].(string), "/")
				if mask_ok {
					dst_ok = ma["cidr_blocks"].(string)
				} else {
					dst_ok = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
				}
				natRule = Rule{
					Action:		ma["action"].(string),
					Chain:      "POSTROUTING",
					Proto:      ma["protocol"].(string),
					Iface:		ma["iface"].(string),
					IP_src:		strings.Replace(src_ok, "/", "_", -1),
					IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
					Dports:     ma["to_port"].(string),
					IP_nat:		ma["nat_ip"].(string),
					Nth_every:	ma["nth_every"].(string),
					Nth_packet:	ma["nth_packet"].(string),
					Position:	ma["position"].(string),
				}
				natRuleNoPos = Rule{
					Action:		ma["action"].(string),
					Chain:      "POSTROUTING",
					Proto:      ma["protocol"].(string),
					Iface:		ma["iface"].(string),
					IP_src:		strings.Replace(src_ok, "/", "_", -1),
					IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
					Dports:     ma["to_port"].(string),
					IP_nat:		ma["nat_ip"].(string),
					Nth_every:	ma["nth_every"].(string),
					Nth_packet:	ma["nth_packet"].(string),
					Position:	"?",
				}
			case ma["action"].(string) == "dnat" :
				mask_ok := strings.Contains(on_cidr, "/")
				if mask_ok {
					dst_ok = on_cidr
				} else {
					dst_ok = strings.Join([]string{on_cidr, "/32"}, "")
				}
				mask_ok = strings.Contains(ma["cidr_blocks"].(string), "/")
				if mask_ok {
					src_ok = ma["cidr_blocks"].(string)
				} else {
					src_ok = strings.Join([]string{ma["cidr_blocks"].(string), "/32"}, "")
				}
				natRule = Rule{
					Action:		ma["action"].(string),
					Chain:      "PREROUTING",
					Proto:      ma["protocol"].(string),
					Iface:		ma["iface"].(string),
					IP_src:		strings.Replace(src_ok, "/", "_", -1),
					IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
					Dports:     ma["to_port"].(string),
					IP_nat:		ma["nat_ip"].(string),
					Nth_every:	ma["nth_every"].(string),
					Nth_packet:	ma["nth_packet"].(string),
					Position:	ma["position"].(string),
				}
				natRuleNoPos = Rule{ 
					Action:		ma["action"].(string),
					Chain:      "PREROUTING",
					Proto:      ma["protocol"].(string),
					Iface:		ma["iface"].(string),
					IP_src:		strings.Replace(src_ok, "/", "_", -1),
					IP_dst:		strings.Replace(dst_ok, "/", "_", -1),
					Dports:     ma["to_port"].(string),
					IP_nat:		ma["nat_ip"].(string),
					Nth_every:	ma["nth_every"].(string),
					Nth_packet:	ma["nth_packet"].(string),
					Position:   "?",
				}
		}
		nat_exists, err := client.NatAPI(natRule, "GET")
		if err != nil {
                return fmt.Errorf("Failed check rules nat for %s", on_cidr, natRule)
        }
		switch {
			case method == "DELETE" :
				if nat_exists {
                    ret, err := client.NatAPI(natRule, "DELETE")
                    if ( !ret || err != nil ) {
                        return fmt.Errorf("Failed delete rules nat %s", on_cidr, natRule)
                    }
                }
            case method == "PUT" :
                if !nat_exists {
					if ma["position"].(string) != "?" {
						rulebadpos, err := client.NatAPI(natRuleNoPos, "GET")
						if err != nil {
							return fmt.Errorf("Failed check rules nat for %s", on_cidr, natRule)
						}
						if rulebadpos {
							ret, err := client.NatAPI(natRuleNoPos, "DELETE")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed delete rules with bad position on nat %s", on_cidr, natRule)
							}
							ret, err = client.NatAPI(natRule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules nat %s", on_cidr, natRule)
							}
						} else {
							ret, err := client.NatAPI(natRule, "PUT")
							if ( !ret || err != nil ) {
								return fmt.Errorf("Failed add rules nat %s", on_cidr, natRule)
							}
						}
					} else {	
						ret, err := client.NatAPI(natRule, "PUT")
						if ( !ret || err != nil ) {
							return fmt.Errorf("Failed add rules nat %s", on_cidr, natRule)
						}
					}
                }
            case method == "GET" :
                if !nat_exists {
					return fmt.Errorf("No Exist")
                }
        }
	}
	return nil
}
