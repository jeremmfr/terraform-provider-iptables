# iptables_project_ipv6

Create chain in table filter for specific CIDR ranges (project) and route traffic of CIDR ranges for chain INPUT,FORWARD,OUTPUT in this chain

## Example Usage

```hcl
resource iptables_project_ipv6 theproject {
  name = "theproject"
  cidr_blocks = [
    "2001:db8::/64",
  ]
}
```

## Argument Reference

* **name** : (Required)(ForceNew) name of chain
* **cidr_blocks** : (Required) list of cidr for route in this chain
* **position** : (Optional) position in router_chain (create a specific router_chain for the position and add cidr_blocks in this chain)
