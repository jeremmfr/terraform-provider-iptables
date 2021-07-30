package iptables

import (
	"context"
	"log"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	vaultapi "github.com/hashicorp/vault/api"
)

// Config provider.
type Config struct {
	https            bool
	ipv6Enable       bool
	insecure         bool
	vaultEnable      bool
	noAddDefaultDrop bool
	firewallPortAPI  int
	firewallIP       string
	logname          string
	login            string
	password         string
	vaultPath        string
	vaultKey         string
	allowedIPs       []interface{}
}

// Client configures with Config.
func (c *Config) Client(ctx context.Context) (*Client, diag.Diagnostics) {
	var client *Client
	var err error
	if !c.vaultEnable {
		client, err = NewClient(ctx, c, c.login, c.password)
	} else {
		login, password := getloginVault(c.vaultPath, c.firewallIP, c.vaultKey)
		client, err = NewClient(ctx, c, login, password)
	}
	if err != nil {
		return nil, diag.FromErr(err)
	}

	log.Printf("[INFO] Firewall client configured for server %s", c.firewallIP)

	return client, nil
}

func getloginVault(path string, firewallIP string, key string) (string, string) {
	login := ""
	password := ""
	client, err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "", ""
	}

	c := client.Logical()
	if key != "" {
		secret, err := c.Read(strings.Join([]string{"/secret/", path, "/", key}, ""))
		if err != nil {
			return "", ""
		}
		if secret != nil {
			for key, value := range secret.Data {
				if key == "login" {
					login = value.(string)
				}
				if key == "password" {
					password = value.(string)
				}
			}
		}
	} else {
		secret, err := c.Read(strings.Join([]string{"/secret/", path, "/", firewallIP}, ""))
		if err != nil {
			return "", ""
		}
		if secret != nil {
			for key, value := range secret.Data {
				if key == "login" {
					login = value.(string)
				}
				if key == "password" {
					password = value.(string)
				}
			}
		}
	}

	return login, password
}
