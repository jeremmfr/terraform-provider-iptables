package main

import (
	"github.com/jeremmfr/terraform-provider-iptables/iptables"

	"github.com/hashicorp/terraform-plugin-sdk/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: iptables.Provider,
	})
}
