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

	"github.com/hashicorp/terraform/helper/schema"
)

func resourceProject() *schema.Resource {
	return &schema.Resource{
		Create: resourceProjectCreate,
		Read:   resourceProjectRead,
		Update: resourceProjectUpdate,
		Delete:	resourceProjectDelete,
		Schema: map[string]*schema.Schema{
			"name": &schema.Schema{
				Type:		schema.TypeString,
				Required:	true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if len(value) > 30 {
						errors = append(errors, fmt.Errorf(
							"%q cannot be longer than 30 characters", k))
						}
					return
				},
			},
			"cidr_blocks": &schema.Schema{
				Type:		schema.TypeList,
				Required:	true,
				Elem:		&schema.Schema{Type: schema.TypeString},
			},
		},
	}
}

func resourceProjectCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	checkExists, err := client.ChainAPI(d.Get("name").(string),"GET")
	if err != nil {
		return fmt.Errorf("Failed check if project %s exist", d.Get("name"))
	}
	if !checkExists {
		create, err := client.ChainAPI(d.Get("name").(string),"PUT")
		if ( !create || err != nil ) {
			return fmt.Errorf("Failed create project %s", d.Get("name"))
		}
	} else {
		return fmt.Errorf("ERROR project %s already exist", d.Get("name"))
	}
	d.SetId(d.Get("name").(string) + "!")
	return resourceProjectUpdate(d, m)
}

func resourceProjectRead(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	checkExists, err := client.ChainAPI(d.Get("name").(string),"GET")
	if err != nil {
		return fmt.Errorf("Failed read project %s", d.Get("name"))
	}
	if !checkExists {
		d.SetId("")
	} else {
		d.SetId(d.Get("name").(string) + "!")
	}
	return nil
}

func resourceProjectUpdate(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	if d.HasChange("name") {
		o, n := d.GetChange("name")
		if o != "" {
			err := client.mvChain(o.(string), n.(string))
			if err != nil {
				d.Set("name", o)
				return fmt.Errorf("Failed rename procjet %s", o.(string), " to ", n.(string))
			}
		}
	}
	if d.HasChange("cidr_blocks") {
		o, n := d.GetChange("cidr_blocks")
		cidr_list_add, cidr_list_remove := calcAddRemove(o.([]interface{}), n.([]interface{}))
		for _, cidr := range cidr_list_remove {
			err := 	cidrforprocjet(cidr.(string), "DELETE", d , m )
			if err != nil {
				d.Set("cidr_blocks", o)
				return err
            }
		}
		for _, cidr := range cidr_list_add {
			err := 	cidrforprocjet(cidr.(string), "PUT", d , m )
			if err != nil {
				d.Set("cidr_blocks", o)
				return err
            }
		}

		err := client.save()
		if err != nil {
			return fmt.Errorf("Failed iptables save")
		}
	}
	return nil
}

func resourceProjectDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	cidr_list_remove := d.Get("cidr_blocks").([]interface{})
	for _, cidr := range cidr_list_remove {
		err :=  cidrforprocjet(cidr.(string), "DELETE", d , m )
		if err != nil {
                   return err
        }
	}
	delete, err := client.ChainAPI(d.Get("name").(string),"DELETE")
	if ( !delete || err != nil ) {
		return fmt.Errorf("Failed delete project %s", d.Get("name"))
	}
	d.SetId("")
	err = client.save()
	if err != nil {
		return fmt.Errorf("Failed iptables save")
	}
	return nil
}

func cidrforprocjet(cidr string, method string, d *schema.ResourceData, m interface{}) error {

// Route for source cidr
	client := m.(*Client)
	route := Rule{
		Action: d.Get("name").(string),
		Chain: "router_chain",
		Proto: "all",
		Iface_in: "*",
		Iface_out: "*",
		IP_src: strings.Replace(cidr, "/", "_", -1),
		IP_dst: "0.0.0.0_0",
		Sports: "0",
		Dports: "0",
	}

// Apply on table filter route for source cidr

	routeexists, err := client.RulesAPI(route, "GET")
	if err != nil {
		return fmt.Errorf("Failed check rules for cidr %s", cidr)
	}
	if !routeexists && method == "PUT" {
		routeCIDR, err := client.RulesAPI(route, "PUT")
		if ( !routeCIDR || err != nil ) {
			return fmt.Errorf("Failed create rules source for cidr %s", cidr)
		}
	}
	if routeexists && method == "DELETE" {
		routeCIDR, err := client.RulesAPI(route, "DELETE")
		if ( !routeCIDR || err != nil ) {
			return fmt.Errorf("Failed delete rules source for cidr %s", cidr)
		}
	}

// Route for destination cidr
	route = Rule{
		Action: d.Get("name").(string),
		Chain: "router_chain",
		Proto: "all",
		Iface_in: "*",
		Iface_out: "*",
		IP_src: "0.0.0.0_0",
		IP_dst: strings.Replace(cidr, "/", "_", -1),
		Sports: "0",
		Dports: "0",
	} 
// Apply on table filter route for destination cidr
	routeexists, err = client.RulesAPI(route, "GET")
	if err != nil {
		return fmt.Errorf("Failed check rules for cidr %s", cidr)
	}
	if !routeexists && method == "PUT" {
		routeCIDR, err := client.RulesAPI(route, "PUT")
		if ( !routeCIDR || err != nil ) {
			return fmt.Errorf("Failed create rules destination for cidr %s", cidr)
		}
	}
	if routeexists && method == "DELETE" {
		routeCIDR, err := client.RulesAPI(route, "DELETE")
		if ( !routeCIDR || err != nil ) {
			return fmt.Errorf("Failed delete rules destination for cidr %s", cidr)
		}
	}

	return nil
}

