# terraform-provider-iptables

![GitHub release (latest by date)](https://img.shields.io/github/v/release/jeremmfr/terraform-provider-iptables)
[![Registry](https://img.shields.io/badge/registry-doc%40latest-lightgrey?logo=terraform)](https://registry.terraform.io/providers/jeremmfr/iptables/latest/docs)
[![Go Status](https://github.com/jeremmfr/terraform-provider-iptables/workflows/Go%20Tests/badge.svg)](https://github.com/jeremmfr/terraform-provider-iptables/actions)
[![Lint Status](https://github.com/jeremmfr/terraform-provider-iptables/workflows/GolangCI-Lint/badge.svg)](https://github.com/jeremmfr/terraform-provider-iptables/actions)
[![Go Report Card](https://goreportcard.com/badge/github.com/jeremmfr/terraform-provider-iptables)](https://goreportcard.com/report/github.com/jeremmfr/terraform-provider-iptables)

This provider is compatible with this API : [iptables-api](https://github.com/jeremmfr/iptables-api)

## Automatic install (Terraform 0.13 and later)

Add source information inside the Terraform configuration block for automatic provider installation:

```hcl
terraform {
  required_providers {
    iptables = {
      source = "jeremmfr/iptables"
    }
  }
}
```

## Documentation

[registry.terraform.io](https://registry.terraform.io/providers/jeremmfr/iptables/latest/docs)

or in docs :

[terraform-provider-iptables](docs/index.md)  

Resources:

* [iptables_nat](docs/resources/nat.md)
* [iptables_nat_ipv6](docs/resources/nat_ipv6.md)
* [iptables_project](docs/resources/project.md)
* [iptables_project_ipv6](docs/resources/project_ipv6.md)
* [iptables_raw](docs/resources/raw.md)
* [iptables_raw_ipv6](docs/resources/raw_ipv6.md)
* [iptables_rules](docs/resources/rules.md)
* [iptables_rules_ipv6](docs/resources/rules_ipv6.md)

## Compile

```shell
go build
```
