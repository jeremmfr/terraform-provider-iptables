package iptables_test

import (
	"testing"

	"github.com/jeremmfr/terraform-provider-iptables/iptables"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

func TestProvider(t *testing.T) {
	if err := iptables.Provider().InternalValidate(); err != nil {
		t.Fatalf("err: %s", err)
	}
}

func TestProvider_impl(t *testing.T) {
	var _ *schema.Provider = iptables.Provider()
}
