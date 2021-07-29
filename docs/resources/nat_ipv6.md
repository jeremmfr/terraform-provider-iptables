# iptables_nat_ipv6

Create iptables rules in nat table for snat or dnat

## Example usage

```hcl
resource iptables_nat_ipv6 http_v6_8080 {
  name = "http_v6_8080"
  on_cidr_blocks = [
    "2001:db8::ab",
  ]
  dnat {
    iface    = "bond0"
    protocol = "tcp"
    to_port  = "8080"
    nat_ip   = "[2001:db8::a]:80"
  }
}
resource iptables_nat_ipv6 http_v6_bis {
  name = "http_v6_bis"
  on_cidr_blocks = [
    "2001:db8::aa",
  ]
  dnat {
    iface    = "bond0"
    protocol = "tcp"
    to_port  = "80"
    nat_ip   = "2001:db8::a"
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
* **filter_cidr_blocks** : (Optional) [Def: ["::/0"] ] nat only with this destination CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without this destination CIDR block (ConflictWith filter_cidr_blocks)
* **nat_ip** : (Required) New IP source (NAT)

### **dnat** arguments

* **iface** : (Required) interface input
* **position** : (Optional) [Def: "?"] position of rule in chain
* **protocol** : (Optional) [Def: "all"] protocol (Warning: necessary for to\_port
* **to_port** : (Optional) [Def: "0"] Destination port
* **filter_cidr_blocks** : (Optional) [Def: ["::/0"] ] nat only with this source CIDR list
* **except_cidr_blocks** : (Optional) [Def: "" ] nat without source this CIDR block (ConflictWith filter_cidr_blocks)
* **nat_ip** : (Required) New IP destination (NAT). You can specify new destination port if necessary with :port
