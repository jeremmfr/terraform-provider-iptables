# iptables_raw_ipv6

Create iptables rules in raw table

## Example Usage

```hcl
resource "iptables_raw" "notrack" {
  name = "notrack"
  rule {
    protocol      = "tcp"
    iface_in      = "bond0"
    tcpflags_comp = "SYN"
    notrack       = "true"
    to_port       = "80,443"
    action        = "CT"
  }
}
```

## Argument Reference

* **name** : (Required) name of rules
* **rule** : (Optional) rule detail

### **rule** arguments

* **position** : (Optional) [Def: "?"] position of rule in chain
* **chain** : (Optional) [Def: "PREROUTING"] add on chain (PREROUTING, OUTPUT)
* **protocol** : (Optional) [Def: "all"] protocol
* **from_port** : (Optional) [Def: "0"] source port(s)  
(Use comma for list and colon for range)
* **to_port** : (Optional) [Def: "0"] destination port(s)  
(Use comma for list and colon for range)
* **src_cidr_blocks** : (Optional) [Def: "::/0"] source CIDR
* **dst_cidr_blocks** : (Optional) [Def: "::/0"] destination CIDR
* **iface_out** : (Optional) [Def: "\*"] interface output
* **iface_in** : (Optional) [Def: "\*"] interface input
* **action** : (Optional) [Def: "ACCEPT"] Action (ACCEPT, DROP, RETURN, LOG --log-prefix=...)
* **tcpflags_mask** : (Optional) [Def: "SYN,RST,ACK,FIN"] Mask for --tcpflags
* **tcpflags_comp** : (Optional) [Def: ""] Comp for --tcpflags
* **notrack** : (Optional) [Def: false] set true for add --notrack
