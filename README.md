# terraform-provider-iptables

This provider is compatible with this API : https://github.com/oxalide/iptables-api

Compile:
========
go build -o terraform-provider-iptables && mv terraform-provider-iptables /usr/bin/

Config:
=======

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

Resource:
=========

** Project **
-------------

Create chain in table filter for specific CIDR ranges (project) and route trafic of CIDR ranges for chain INPUT,FORWARD,OUTPUT in this chain :

	resource "iptables_project" "theproject" {
		name        = "theproject"
		cidr_blocks = [ "10.10.0.0/22" ]
	}

* **name** : (Required) name of chain
* **cidr_blocks** : (Required) list of cidr for route in this chain

** Rules **
-----------

Create iptables rules in chain (project)

	resource "iptables_rules" "rules-front" {
		name			= "rules-front"
		project			= "${iptables_project.theproject.name}"
		on_cidr_blocks	= [ "10.10.0.1", "10.10.0.2", "10.10.0.16/28" ]
		ingress {
			protocol	= "tcp"
			to_port		= "80,443"
		}
	}

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
* **cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] ] Source CIDR or IP Range list for ingress / Destination CIDR or IP Range list for egress
* **iface_out** : (Optional) [Def: "\*"] interface output
* **iface_in** : (Optional) [Def: "\*"] interface input
* **state** : (Optional) [Def: ""] Connection tracking state
* **icmptype** : (Optional) [Def: ""] Icmptype (with protocol=icmp)
* **fragment** : (Optional) [Def: false] Fragmented packets false/true
* **action** : (Optional) [Def: "ACCEPT"] Action (ACCEPT, DROP, LOG --log-prefix=...)

** Nat **
---------

Create iptables rules in nat table for snat or dnat

	resource "iptables_nat" "dnat-front" {
		name	= "dnat-front"
		on_cidr_blocks = [ "8.8.8.8" ]
		dnat {
			iface		= "bond0"
			protocol	= "tcp"
			to_port		= 8080
			nat_ip		= "10.10.0.1:80"
		}
	}

* **name** : (Required) name of rules
* **on_cidr_blocks** : (Required) apply rule on CIDR list
* **snat** (Optional) Can be specified multiple times for each snat rule (Warning, if only nat\_ip change, only the first nat)
* **dnat** (Optional) Can be specified multiple times for each dnat rule (Warning, if only nat\_ip change, only the first nat)

**snat** block supports : 
* **iface** : (Required) interface output
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] ] nat only with this destination CIDR list
* **nat_ip** : (Required) New IP source (NAT)

**dnat** block supports :
* **iface** : (Required) interface output
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol (Warning: necessary for to\_port
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] ] nat only with this source CIDR list
* **nat\_ip** : (Required) New IP destination (NAT). You can specify new destination port if necessary with :port

** Raw **
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

** Same rules on multiple servers **
====================================

Create directory and add resource in this directory

Create main.tf with this :

	module "server-1" {
		source = "directory"
		firewall_ip = "A.B.C.D"
	}
	module "server-2" {
		source = "directory"
		firewall_ip = "E.F.G.H"

	}

Create variables.tf in directory with :

	variable "firewall_ip" {}

In provider configuration set :

	provider "iptables" {
	    firewall_ip = "${var.firewall_ip}"
		...
	}
