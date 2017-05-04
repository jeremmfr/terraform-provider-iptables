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

import(
	"os"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"firewall_ip": {
				Type:			schema.TypeString,
				Required:		true,
			},
			"port": {
				Type:			schema.TypeInt,
				Optional:		true,
				Default:		8080,
			},
			"allowed_cidr_blocks": &schema.Schema{
				Type:			schema.TypeList,
				Required:		true,
				Elem:			&schema.Schema{Type: schema.TypeString},
            },
			"https": &schema.Schema{
				Type:		schema.TypeBool,
				Optional:	true,
				Default:	false,
			},
			"insecure": {
				Type:		schema.TypeBool,
				Optional:	true,
				Default:	false,
            },
			"login": {
				Type:		schema.TypeString,
				Optional:	true,
				Default:	"",
				ConflictsWith:	[]string{"vault_enable"},
			},
			"password": {
				Type:		schema.TypeString,
				Optional:	true,
				Default:	"",
				ConflictsWith:	[]string{"vault_enable"},
			},
			"vault_enable": {
				Type:		schema.TypeBool,
				Optional:	true,
				Default:	false,
				ConflictsWith:	[]string{"login","password"},
			},
			"vault_path": {
				Type:		schema.TypeString,
				Optional:	true,
				Default:	"lvs",
			},
			"vault_key": {
				Type:		schema.TypeString,
				Optional:	true,
				Default:	"",
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"iptables_project":		resourceProject(),
			"iptables_rules":		resourceRules(),
			"iptables_nat":			resourceNat(),
			"iptables_raw":			resourceRaw(),
		},
		ConfigureFunc: configureProvider,
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		firewall_ip:		d.Get("firewall_ip").(string),
		firewall_port_api:	d.Get("port").(int),
		allowed_ips:		d.Get("allowed_cidr_blocks").([]interface{}),
		https:				d.Get("https").(bool),
		insecure:			d.Get("insecure").(bool),
		logname:			os.Getenv("USER"),
		login:				d.Get("login").(string),
		password:			d.Get("password").(string),
		vault_enable:		d.Get("vault_enable").(bool),
		vault_path:			d.Get("vault_path").(string),
		vault_key:			d.Get("vault_key").(string),
	}
	return config.Client()
}
