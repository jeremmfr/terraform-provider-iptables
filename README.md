# terraform-provider-iptables
[![GoDoc](https://godoc.org/github.com/jeremmfr/terraform-provider-iptables?status.svg)](https://godoc.org/github.com/jeremmfr/terraform-provider-iptables) [![Go Report Card](https://goreportcard.com/badge/github.com/jeremmfr/terraform-provider-iptables)](https://goreportcard.com/report/github.com/jeremmfr/terraform-provider-iptables)
[![Build Status](https://travis-ci.org/jeremmfr/terraform-provider-iptables.svg?branch=master)](https://travis-ci.org/jeremmfr/terraform-provider-iptables)

This provider is compatible with this API : https://github.com/jeremmfr/iptables-api

Compile:
========

export GO111MODULE=on  
go build -o terraform-provider-iptables && mv terraform-provider-iptables /usr/bin/

Config:
=======

The provider adds DROP lines and a router_chain automatically, to disable this:
```
export CONFIG_IPTABLES_TERRAFORM_NODEFAULT=1
```
Setup information for contact server :
```
provider "iptables" {
	firewall_ip = "192.168.0.1"
	port		= 8080
	allowed_cidr_blocks = [ "10.0.0.0/24" ]
	https		= true
	insecure	= true
	vault_enable = true
}
```

* **firewall_ip** : (Required) IP for firewall API (iptables-api)
* **port** : (Optional) [Def: 8080] Port for firewal API (iptables-api)
* **allowed_cidr_blocks** : (Required) list of CIDR allowed to contact API (add iptables rules on start) _no rules removed if remove cidr_
* **https** : (Optional) [Def: false] Use HTTPS for firewall API
* **insecure** : (Optional) [Def: false] Don't check certificate for HTTPS
* **login** : (Optional) [Def: ""] User for http basic authentication
* **password** : (Optional) [Def: ""] Password for http basic authentication
* **vault_enable** : (Optional) [Def: false] Read login/password in secret/$vault_path/$firewall_ip or secret/$vault_path/$vault_key (For server and token, read environnement variables "VAULT_ADDR", "VAULT_TOKEN") ConflictWith **login**/**password**
* **vault_path** : (Optional) [Def: "lvs"] Path where the key are
* **vault_key** : (Optional) [Def: ""] Name of key in vault path
* **ipv6_enable** : (Optional) [Def: false] Add default ipv6 rules (router_chain + DROP)

Resource:
=========

** project (or project_ipv6) **
-------------

Create chain in table filter for specific CIDR ranges (project) and route trafic of CIDR ranges for chain INPUT,FORWARD,OUTPUT in this chain :
```
	resource iptables_project theproject {
		name        = "theproject"
		cidr_blocks = [ "10.10.0.0/22" ]
	}
	resource iptables_project_ipv6 theproject {
		name = "theproject"
		cidr_blocks = [
				"2001:db8::/64",
			]
	}
```
* **name** : (Required)(ForceNew) name of chain
* **cidr_blocks** : (Required) list of cidr for route in this chain
* **position** : (Optional) position in router_chain (create a specific router_chain for the position and add cidr_blocks in this chain)

** rules (or rules_ipv6)**
-----------
```
Create iptables rules in chain (project)

	resource iptables_rules rules-front {
		name			= "rules-front"
		project			= iptables_project.theproject.name
		on_cidr_blocks	= [ "10.10.0.1", "10.10.0.2", "10.10.0.16/28" ]
		ingress {
			protocol	= "tcp"
			to_port		= "80,443"
		}
	}
	resource iptables_rules_ipv6 http_ipv6 {
		name = "http_ipv6"
		project = iptables_project_ipv6.theproject.name
		on_cidr_blocks = [
				"2001:db8::a",
				"2001:db8::b",
				"2001:db8::ab",
              ]
		ingress {
			protocol = "tcp"
			to_port = "80"
		}
	}
```

* **name** : (Required) name of rules
* **project** : (Required) apply on chain *project*
* **on_cidr_blocks** : (Required) apply rule on CIDR or IP Range list
* **ingress** : (Optional) Can be specified multiple times for each ingress rule
* **egress** : (Optional) Can be specified multiple times for each egress rule

**ingress** and **egress** block supports :
* **position** : (Optional) [Def: "?"] position of rule in chain
* **from_port** : (Optional) [Def: "0"] source port(s)
(Use comma for list and colon for range)
* **to_port** : (Optional) [Def: "0"] destination port(s)
(Use comma for list and colon for range)
* **protocol** : (Optional) [Def: "all"] protocol
* **cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] (["::/0"] for v6)] Source CIDR or IP Range list for ingress / Destination CIDR or IP Range list for egress
* **iface_out** : (Optional) [Def: "\*"] interface output
* **iface_in** : (Optional) [Def: "\*"] interface input
* **state** : (Optional) [Def: ""] Connection tracking state
* **icmptype** : (Optional) [Def: ""] Icmptype (with protocol=icmp or ipv6-icmp)
* **fragment** : (Optional) [Def: false] Fragmented packets false/true
* **action** : (Optional) [Def: "ACCEPT"] Action (ACCEPT, DROP, LOG --log-prefix=...)

** nat (or nat_ipv6) **
---------

Create iptables rules in nat table for snat or dnat
```
	resource iptables_nat dnat-front_http {
		name	= "dnat-front_http"
		on_cidr_blocks = [ "203.0.113.1" ]
		dnat {
			iface		= "bond0"
			protocol	= "tcp"
			to_port		= 80
			nat_ip		= "10.10.0.1"
		}
	}
	resource iptables_nat dnat-front {
		name	= "dnat-front"
		on_cidr_blocks = [ "203.0.113.1" ]
		dnat {
			iface		= "bond0"
			protocol	= "tcp"
			to_port		= 8080
			nat_ip		= "10.10.0.1:80"
		}
	}
	resource iptables_nat_ipv6 http_v6_8080 {
		name = "http_v6_8080"
        	on_cidr_blocks = [
			"2001:db8::ab",
		]
		dnat {
			iface = "bond0"
			protocol = "tcp"
			to_port = "8080"
			nat_ip = "[2001:db8::a]:80"
		}
	}
	resource iptables_nat_ipv6 http_v6_bis {
		name = "http_v6_bis"
		on_cidr_blocks = [
			"2001:db8::aa",
			]
		dnat {
			iface = "bond0"
			protocol = "tcp"
			to_port = "80"
			nat_ip = "2001:db8::a"
		}
	}
```

* **name** : (Required) name of rules
* **on_cidr_blocks** : (Required) apply rule on CIDR list
* **snat** (Optional) Can be specified multiple times for each snat rule
* **dnat** (Optional) Can be specified multiple times for each dnat rule

**snat** block supports :
* **iface** : (Required) interface output
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] (["::/0"] for v6)] nat only with this destination CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without this destination CIDR block (ConflictWith filter_cidr_blocks)
* **nat_ip** : (Required) New IP source (NAT)

**dnat** block supports :
* **iface** : (Required) interface input
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol (Warning: necessary for to\_port
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] (["::/0"] for v6)] nat only with this source CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without source this CIDR block (ConflictWith filter_cidr_blocks)
* **nat\_ip** : (Required) New IP destination (NAT). You can specify new destination port if necessary with :port

** raw (or raw_ipv6) **
---------

Create iptables rules in raw table

	resource "iptables_raw" "notrack" {
		name = "notrack"
		rule {
			protocol		= "tcp"
			iface_in		= "bond0"
			tcpflags_comp	= "SYN"
			notrack			= "true"
			to_port			= "80,443"
			action			= "CT"
		}
	}

* **name** : (Required) name of rules
* **rule** : (Optional) rule detail

**rule** block supports :
* **position** : (Optional) [Def: "?"] position of rule in chain
* **chain** : (Optional) [Def: "PREROUTING"] add on chain (PREROUTING, OUTPUT)
* **protocol** : (Optional) [Def: "all"] protocol
* **from_port** : (Optional) [Def: "0"] source port(s)
(Use comma for list and colon for range)
* **to_port** : (Optional) [Def: "0"] destination port(s)
(Use comma for list and colon for range)
* **src_cidr_blocks** : (Optional) [Def: "0.0.0.0/0"] source CIDR
* **dst_cidr_blocks** : (Optional) [Def: "0.0.0.0/0"] destination CIDR
* **iface_out** : (Optional) [Def: "\*"] interface output
* **iface_in** : (Optional) [Def: "\*"] interface input
* **action** : (Optional) [Def: "ACCEPT"] Action (ACCEPT, DROP, RETURN, LOG --log-prefix=...)
* **tcpflags_mask** : (Optional) [Def: "SYN,RST,ACK,FIN"] Mask for --tcpflags
* **tcpflags_comp** : (Optional) [Def: ""] Comp for --tcpflags
* **notrack** : (Optional) [Def: false] set true for add --notrack
