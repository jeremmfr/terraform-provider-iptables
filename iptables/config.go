// Copyright 2017 Jeremy Muriel
//
// This file is part of terraform-provider-iptables.
//
// terraform-provider-iptables is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// Foobar is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with terraform-provider-iptables.  If not, see <http://www.gnu.org/licenses/>.

package iptables

import (
	"fmt"
	"log"
	"strings"

	vaultapi "github.com/hashicorp/vault/api"
)
type Config struct {
	firewall_ip			string
	firewall_port_api	int
	allowed_ips			[]interface{}
	https				bool
	insecure			bool
	logname				string
	login				string
	password			string
	vault_enable		bool
	vault_path			string
	vault_key			string
}	

func (c *Config)  Client() (*Client, error) {
	var client *Client
	var err error
	if c.vault_enable == false {
		client, err = NewClient(c.firewall_ip, c.firewall_port_api, c.allowed_ips, c.https, c.insecure, c.logname, c.login, c.password)
	} else {
		login, password := GetloginVault(c.vault_path, c.firewall_ip, c.vault_key)
		client, err = NewClient(c.firewall_ip, c.firewall_port_api, c.allowed_ips, c.https, c.insecure, c.logname, login, password)
	}
	if err != nil {
		return nil, fmt.Errorf("Error setting up firewall client %s", err)
	}

	log.Printf("[INFO] Firewall client configured for server %s", c.firewall_ip)
	return client, nil
}

func GetloginVault(path string, firewall_ip string, key string) (string,string) {
	login := ""
	password := ""
	client,err := vaultapi.NewClient(vaultapi.DefaultConfig())
	if err != nil {
		return "",""
	}
	
	c := client.Logical()
	if key != "" {
		secret, err := c.Read(strings.Join([]string{"/secret/", path, "/", key}, ""))
		if err != nil {
			return "",""
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
		secret, err := c.Read(strings.Join([]string{"/secret/", path, "/", firewall_ip}, ""))
		if err != nil {
			return "",""
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
	return login,password
}
