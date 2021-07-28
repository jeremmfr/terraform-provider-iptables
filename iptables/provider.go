package iptables

import (
	"os"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	strAll           = "all"
	httpGet          = "GET"
	httpPut          = "PUT"
	httpDel          = "DELETE"
	wayIngress       = "in"
	wayEgress        = "out"
	ipv4All          = "0.0.0.0/0"
	ipv6All          = "::/0"
	ipv4ver          = "ipv4"
	ipv6ver          = "ipv6"
	noExistsNoPosErr = noExists + "_but_nopos"
	noExists         = "no_exists"
)

const (
	defaultFirewallPort = 8080
	one                 = 1
)

// Provider iptables for terraform.
func Provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"firewall_ip": {
				Type:     schema.TypeString,
				Required: true,
			},
			"port": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  defaultFirewallPort,
			},
			"allowed_cidr_blocks": {
				Type:     schema.TypeSet,
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
			"no_add_default_drop": {
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
		firewallIP:       d.Get("firewall_ip").(string),
		firewallPortAPI:  d.Get("port").(int),
		allowedIPs:       d.Get("allowed_cidr_blocks").(*schema.Set).List(),
		https:            d.Get("https").(bool),
		insecure:         d.Get("insecure").(bool),
		logname:          os.Getenv("USER"),
		login:            d.Get("login").(string),
		password:         d.Get("password").(string),
		vaultEnable:      d.Get("vault_enable").(bool),
		vaultPath:        d.Get("vault_path").(string),
		vaultKey:         d.Get("vault_key").(string),
		ipv6Enable:       d.Get("ipv6_enable").(bool),
		noAddDefaultDrop: d.Get("no_add_default_drop").(bool),
	}

	return config.Client()
}
