# iptables Provider

This provider is compatible with this API : [iptables-api](https://github.com/jeremmfr/iptables-api)

The provider adds DROP lines and a router_chain automatically, to disable this:

```shell
export CONFIG_IPTABLES_TERRAFORM_NODEFAULT=1
```

## Example Usage

```hcl
provider "iptables" {
  firewall_ip         = "192.168.0.1"
  port                = 8080
  allowed_cidr_blocks = ["10.0.0.0/24"]
  https               = true
  insecure            = true
  vault_enable        = true
}
```

## Argument Reference

* **firewall_ip** : (Required) IP for firewall API (iptables-api)
* **port** : (Optional) [Def: 8080] Port for firewall API (iptables-api)
* **allowed_cidr_blocks** : (Required) list of CIDR allowed to contact API (add iptables rules on start)
* **https** : (Optional) [Def: false] Use HTTPS for firewall API
* **insecure** : (Optional) [Def: false] Don't check certificate for HTTPS
* **login** : (Optional) [Def: ""] User for http basic authentication
* **password** : (Optional) [Def: ""] Password for http basic authentication
* **vault_enable** : (Optional) [Def: false] Read login/password in secret/$vault_path/$firewall_ip or secret/$vault_path/$vault_key  
(For server and token, read environnement variables "VAULT_ADDR", "VAULT_TOKEN") ConflictWith **login**/**password**
* **vault_path** : (Optional) [Def: "lvs"] Path where the key are
* **vault_key** : (Optional) [Def: ""] Name of key in vault path
* **ipv6_enable** : (Optional) [Def: false] Add default ipv6 rules (router_chain + DROP)
* **no_add_default_drop** : (Optional) [Def: false] Don't add drop rules in (INPUT,FORWARD,OUTPUT)

!> **Warning** no iptables rules removed when remove cidr of `allowed_cidr_blocks` list
