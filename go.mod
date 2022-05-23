module github.com/jeremmfr/terraform-provider-iptables

go 1.15

require (
	github.com/hashicorp/go-cty v1.4.1-0.20200414143053-d3edf31b6320
	github.com/hashicorp/terraform-plugin-sdk/v2 v2.16.0
	github.com/hashicorp/vault/api v1.1.1
)

replace github.com/hashicorp/terraform-plugin-sdk/v2 => github.com/jeremmfr/terraform-plugin-sdk/v2 v2.16.1-0.20220517115548-d52b104279ff
