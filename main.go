package main

import (
	"terraform-provider-iptables/iptables"

	"github.com/hashicorp/terraform/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: iptables.Provider,
	})
}
