package iptables

import (
	"os"

	"github.com/hashicorp/terraform/helper/schema"
	"github.com/hashicorp/terraform/terraform"
)

const strAll string = "all"
const httpGet string = "GET"
const httpPut string = "PUT"
const httpDel string = "DELETE"
const wayIngress string = "in"
const wayEgress string = "out"
const ipv4All string = "0.0.0.0/0"
const ipv6All string = "::/0"
const ipv4ver string = "ipv4"
const ipv6ver string = "ipv6"

// Provider iptables for terraform
func Provider() terraform.ResourceProvider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"firewall_ip": {
				Type:     schema.TypeString,
				Required: true,
			},
			"port": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  8080,
			},
			"allowed_cidr_blocks": {
				Type:     schema.TypeList,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"https": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"insecure": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
			"login": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"password": {
				Type:     schema.TypeString,
				Optional: true,
			},
			"vault_enable": {
				Type:          schema.TypeBool,
				Optional:      true,
				Default:       false,
				ConflictsWith: []string{"login", "password"},
			},
			"vault_path": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "lvs",
			},
			"vault_key": {
				Type:     schema.TypeString,
				Optional: true,
				Default:  "",
			},
			"ipv6_enable": {
				Type:     schema.TypeBool,
				Optional: true,
				Default:  false,
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"iptables_project": resourceProject(),
			"iptables_rules":   resourceRules(),
			"iptables_nat":     resourceNat(),
			"iptables_raw":     resourceRaw(),

			"iptables_project_ipv6": resourceProjectIPv6(),
			"iptables_rules_ipv6":   resourceRulesIPv6(),
			"iptables_nat_ipv6":     resourceNatIPv6(),
			"iptables_raw_ipv6":     resourceRawIPv6(),
		},
		ConfigureFunc: configureProvider,
	}
}

func configureProvider(d *schema.ResourceData) (interface{}, error) {
	config := Config{
		firewallIP:      d.Get("firewall_ip").(string),
		firewallPortAPI: d.Get("port").(int),
		allowedIPs:      d.Get("allowed_cidr_blocks").([]interface{}),
		https:           d.Get("https").(bool),
		insecure:        d.Get("insecure").(bool),
		logname:         os.Getenv("USER"),
		login:           d.Get("login").(string),
		password:        d.Get("password").(string),
		vaultEnable:     d.Get("vault_enable").(bool),
		vaultPath:       d.Get("vault_path").(string),
		vaultKey:        d.Get("vault_key").(string),
		ipv6Enable:      d.Get("ipv6_enable").(bool),
	}
	return config.Client()
}
