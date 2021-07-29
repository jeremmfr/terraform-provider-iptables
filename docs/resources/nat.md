# iptables_nat

Create iptables rules in nat table for snat or dnat

## Example Usage

```hcl
resource iptables_nat dnat-front_http {
  name           = "dnat-front_http"
  on_cidr_blocks = ["203.0.113.1"]
  dnat {
    iface    = "bond0"
    protocol = "tcp"
    to_port  = 80
    nat_ip   = "10.10.0.1"
  }
}
resource iptables_nat dnat-front {
  name           = "dnat-front"
  on_cidr_blocks = ["203.0.113.1"]
  dnat {
    iface    = "bond0"
    protocol = "tcp"
    to_port  = 8080
    nat_ip   = "10.10.0.1:80"
  }
}
```

## Argument Reference

* **name** : (Required) name of rules
* **on_cidr_blocks** : (Required) apply rule on CIDR list
* **snat** (Optional) Can be specified multiple times for each snat rule
* **dnat** (Optional) Can be specified multiple times for each dnat rule

### **snat** arguments

* **iface** : (Required) interface output
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] ] nat only with this destination CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without this destination CIDR block (ConflictWith filter_cidr_blocks)
* **nat_ip** : (Required) New IP source (NAT)

### **dnat** arguments

* **iface** : (Required) interface input
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol (Warning: necessary for to\_port
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["0.0.0.0/0"] ] nat only with this source CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without source this CIDR block (ConflictWith filter_cidr_blocks)
* **nat_ip** : (Required) New IP destination (NAT). You can specify new destination port if necessary with :port
