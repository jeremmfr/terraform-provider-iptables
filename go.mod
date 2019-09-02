module github.com/jeremmfr/terraform-provider-iptables

go 1.12

require (
	github.com/hashicorp/terraform v0.12.7
	github.com/hashicorp/vault v1.1.2
	github.com/ryanuber/go-glob v1.0.0 // indirect
)

replace git.apache.org/thrift.git => github.com/apache/thrift v0.12.0
