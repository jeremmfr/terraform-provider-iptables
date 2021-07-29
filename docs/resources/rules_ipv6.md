# iptables_rules_ipv6

Create iptables rules in chain (project)

## Example Usage

```hcl
resource iptables_rules_ipv6 http_ipv6 {
  name    = "http_ipv6"
  project = iptables_project_ipv6.theproject.name
  on_cidr_blocks = [
    "2001:db8::a",
    "2001:db8::b",
    "2001:db8::ab",
  ]
  ingress {
    protocol = "tcp"
    to_port  = "80"
  }
}
```

## Argument Reference

* **name** : (Required) name of rules
* **project** : (Required) apply on chain *project*
* **on_cidr_blocks** : (Required) apply rule on CIDR or IP Range list
* **ingress** : (Optional) Can be specified multiple times for each ingress rule
* **egress** : (Optional) Can be specified multiple times for each egress rule

### **ingress** and **egress**  arguments

* **position** : (Optional) [Def: "?"] position of rule in chain
* **from_port** : (Optional) [Def: "0"] source port(s)
(Use comma for list and colon for range)
* **to_port** : (Optional) [Def: "0"] destination port(s)
(Use comma for list and colon for range)
* **protocol** : (Optional) [Def: "all"] protocol
* **cidr_blocks** : (Optional) [Def: ["::/0"] ] Source CIDR or IP Range list for ingress / Destination CIDR or IP Range list for egress
* **iface_out** : (Optional) [Def: "\*"] interface output
* **iface_in** : (Optional) [Def: "\*"] interface input
* **state** : (Optional) [Def: ""] Connection tracking state
* **icmptype** : (Optional) [Def: ""] Icmp type (with protocol=icmp or ipv6-icmp)
* **fragment** : (Optional) [Def: false] Fragmented packets false/true
* **action** : (Optional) [Def: "ACCEPT"] Action (ACCEPT, DROP, LOG --log-prefix=...)
