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
	"net/http"
	"fmt"
	"io/ioutil"
	"errors"
	"strings"
	"log"
	"strconv"
	"crypto/tls"
)

type Client struct {
    Firewall_IP string
	Port		int	
	Allowed_IPs []interface{}
	Https		bool
	Insecure	bool
	Logname		string
	Login		string
	Password	string
}

type Rule struct {
	Action		string
	State		string
	Icmptype	string
	Fragment	bool
	Chain		string
	Proto		string
	Iface_in	string
	Iface_out	string
	Iface		string
	IP_src		string
	IP_dst		string
	IP_nat		string
	Sports		string
	Dports		string
	Tcpflags_1	string
	Tcpflags_2	string
	Notrack		bool
	Position	string
	Nth_every	string
	Nth_packet	string
	Logprefix	string
}

func NewClient(firewall_ip string, firewall_port_api int, allowed_ips []interface{}, https bool, insecure bool, logname string, login string, password string) (*Client,error) {
	client := &Client{
			Firewall_IP	: firewall_ip,
			Port		: firewall_port_api,
			Allowed_IPs : allowed_ips,
			Https		: https,
			Insecure	: insecure,
			Logname		: logname,
			Login		: login,
			Password	: password,
	}

    checkExists_router, err := client.ChainAPI("router_chain","GET")
    if err != nil {
		return nil, err
	}
	if !checkExists_router {
		createChain, err := client.ChainAPI("router_chain", "PUT")
	    if ( !createChain || err != nil ) {
			return nil,fmt.Errorf("Failed create chain router")
		}
	}
//	Add Allowed_IPs on TCP Firewal_IP:Port
	for _, cidr := range client.Allowed_IPs {
// raw notrack on Firewal_IP:Port
		acceptAPI := Rule{
			Action: "CT",
			Chain:	"PREROUTING",
			Proto: "tcp",
			Iface_in: "*",
			Iface_out: "*",
			IP_src: strings.Replace(cidr.(string), "/", "_", -1),
			IP_dst: client.Firewall_IP,
			Sports: "0",
			Dports: strconv.Itoa(client.Port),
			Tcpflags_1: "SYN,RST,ACK,FIN",
			Tcpflags_2: "SYN",
			Notrack: true,
			Position: "?",
		}
		routeexists, err := client.RawAPI(acceptAPI, "GET")
		if err != nil {
			return nil,fmt.Errorf("[ERROR] Failed check rules (raw) allowed IP for API for cidr %s", cidr.(string))
		}
		if !routeexists {
			routeCIDR, err := client.RawAPI(acceptAPI, "PUT")
			if ( !routeCIDR || err != nil ) {
				return nil,fmt.Errorf("[ERROR] Failed create rules (raw) allowed IP for API for cidr %s", cidr.(string))
			}
		}
			
// ingress on Firewal_IP:Port
		acceptAPI = Rule{
			Action: "ACCEPT",
			Chain: "router_chain",
			Proto: "tcp",
			Iface_in: "*",
			Iface_out: "*",
			IP_src: strings.Replace(cidr.(string), "/", "_", -1),
			IP_dst: client.Firewall_IP,
			Sports: "0",
			Dports: strconv.Itoa(client.Port),
			Position: "?",
		}
		routeexists, err = client.RulesAPI(acceptAPI, "GET")
		if err != nil {
			return nil,fmt.Errorf("[ERROR] Failed check rules (ingress) allowed IP for API for cidr %s", cidr.(string))
		}
		if !routeexists {
			routeCIDR, err := client.RulesAPI(acceptAPI, "PUT")
			if ( !routeCIDR || err != nil ) {
				return nil,fmt.Errorf("[ERROR] Failed create rules (ingress) allowed IP for API for cidr %s", cidr.(string))
			}
		}

// egress on Firewal_IP:Port
		acceptAPI = Rule{
			Action: "ACCEPT",
			Chain: "router_chain",
			Proto: "tcp",
			Iface_in: "*",
			Iface_out: "*",
			IP_src: client.Firewall_IP,
			IP_dst: strings.Replace(cidr.(string), "/", "_", -1),
			Sports: strconv.Itoa(client.Port),
			Dports: "0",
			Position: "?",
		}
		routeexists, err = client.RulesAPI(acceptAPI, "GET")
		if err != nil {
			return nil,fmt.Errorf("[ERROR] Failed check rules (egress) allowed IP for API for cidr %s", cidr.(string))
		}
		if !routeexists {
			routeCIDR, err := client.RulesAPI(acceptAPI, "PUT")
			if ( !routeCIDR || err != nil ) {
				return nil,fmt.Errorf("[ERROR] Failed create rules (egress) allowed IP for API for cidr %s", cidr.(string))
			}
		}
	}
	
// Add rules for default chain
	default_table := []string{"INPUT", "FORWARD", "OUTPUT"}
	for _, table := range default_table {
		route_default := Rule{
			Action: "router_chain",
			Chain: table,
			Proto: "all",
			Iface_in: "*",
			Iface_out: "*",
			IP_src: "0.0.0.0_0",
			IP_dst: "0.0.0.0_0",
			Sports: "0",
			Dports: "0",
			Position: "?",
		}
		ruleexists, err := client.RulesAPI(route_default, "GET")
		if err != nil {
			return nil,fmt.Errorf("[ERROR] check default rules %s", table)
		}
		if !ruleexists {
			resp, err := client.RulesAPI(route_default, "PUT")
			if ( !resp || err != nil ) {
				return nil,fmt.Errorf("[ERROR] Failed create default rules %s", table)
			}
		}
		rule_drop := Rule{
			Action: "DROP",
			Chain: table,
			Proto: "all",
			Iface_in: "*",
			Iface_out: "*",
			IP_src: "0.0.0.0_0",
			IP_dst: "0.0.0.0_0",
			Sports: "0",
			Dports: "0",
			Position: "?",
		}
		ruleexists, err = client.RulesAPI(rule_drop, "GET")
		if err != nil {
			return nil,fmt.Errorf("[ERROR] check default rules drop %s", table)
		}
		if !ruleexists {
			resp, err := client.RulesAPI(rule_drop, "PUT")
			if ( !resp || err != nil ) {
				return nil,fmt.Errorf("[ERROR] Failed create default rules drop %s", table)
			}
		}
	}

	return client, nil
}

func (c *Client)  newRequest(method string, url string) (*http.Request, error) {
	IP := c.Firewall_IP
	port := strconv.Itoa(c.Port)
	
	matched := strings.Contains(url, "?")
	url_str := ""
	if matched {
		url_str = "http://" + IP + ":" + port + url + "&logname=" + c.Logname
	} else {
		url_str = "http://" + IP + ":" + port + url + "?&logname=" + c.Logname
	}
	if c.Https {
		url_str = strings.Replace(url_str, "http://", "https://", -1)
	}
	req, err := http.NewRequest(method, url_str, nil)
	if c.Login != "" && c.Password != "" {
		req.SetBasicAuth(c.Login, c.Password)
	}
	log.Printf("[INFO] New API request: %s", method, url_str)
	if err != nil {
        return nil, fmt.Errorf("Error during creation of request: %s", err)
    }
	return req, nil
}

func (client *Client) RulesAPI(rule Rule, method string) (bool, error) {
	url_str_1 := []string{"/rules/", rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.Iface_in, "/", rule.Iface_out, "/", rule.IP_src, "/", rule.IP_dst, "/"}
	var url_str []string
	if (rule.Sports != "0") || (rule.Dports != "0") || (rule.State != "") || (rule.Icmptype != "") || (rule.Fragment == true) || (rule.Position != "?") || (rule.Logprefix != "") {
		url_str = append(url_str_1, "?")
		if rule.Sports != "0" {
			url_str = append(url_str, "&sports=", rule.Sports)
		}
		if rule.Dports != "0" {
			url_str = append(url_str, "&dports=", rule.Dports)
		}
		if rule.State != "" {
			url_str = append(url_str, "&state=", rule.State)
		}
		if rule.Icmptype != "" {
			url_str = append(url_str, "&icmptype=", rule.Icmptype)
		}
		if rule.Fragment == true {
			url_str = append(url_str, "&fragment=true")
		}
		if rule.Position != "?" {
			url_str = append(url_str, "&position=", rule.Position)
		}
		if rule.Logprefix != "" {
			url_str = append(url_str, "&log-prefix=", rule.Logprefix)
		}
	} else {
		url_str = url_str_1
	}
	
	req, err := client.newRequest(method, strings.Join(url_str, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))

	if resp.StatusCode == 200 {
		return true, nil
	}
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode == 409 {
		return false, errors.New("Conflict with position")
	}
	return false, errors.New(string(body))
}

func (client *Client) NatAPI(rule Rule, method string) (bool, error) {
	url_str_1 := []string{"/nat/", rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.Iface, "/", rule.IP_src, "/", rule.IP_dst, "/", rule.IP_nat, "/"}
	var url_str []string
	if (rule.Dports != "0") || (rule.Position != "?") || (rule.Nth_every != "") {
		url_str = append(url_str_1, "?")
		if rule.Dports != "0" {
			url_str = append(url_str, "&dport=", rule.Dports)
		}
		if rule.Position != "?" {
			url_str = append(url_str, "&position=", rule.Position)
		}
		if rule.Nth_every != "" {
			url_str = append(url_str, "&nth_every=", rule.Nth_every, "&nth_packet=", rule.Nth_packet)
		}
	} else {
		url_str = url_str_1
	}
	
	req, err := client.newRequest(method, strings.Join(url_str, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))

	if resp.StatusCode == 200 {
		return true, nil
	}
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode == 409 {
		return false, errors.New("Conflict with position")
	}
	return false, errors.New(string(body))
}
func (client *Client) RawAPI(rule Rule, method string) (bool, error) {
	url_str_1 := []string{"/raw/", rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.Iface_in, "/", rule.Iface_out, "/", rule.IP_src, "/", rule.IP_dst, "/"}
	var url_str []string
	if (rule.Sports != "0") || (rule.Dports != "0") || (rule.Tcpflags_1 != "") || (rule.Tcpflags_2 != "") || (rule.Notrack == true) || (rule.Position != "?") || (rule.Logprefix != "") {
		url_str = append(url_str_1, "?")
		if rule.Sports != "0" {
			url_str = append(url_str, "&sports=", rule.Sports)
		}
		if rule.Dports != "0" {
			url_str = append(url_str, "&dports=", rule.Dports)
		}
		if (rule.Tcpflags_1 != "") && (rule.Tcpflags_2 != "") {
			url_str = append(url_str, "&tcpflag1=", rule.Tcpflags_1, "&tcpflag2=", rule.Tcpflags_2)
		}
		if rule.Notrack == true {
			url_str = append(url_str, "&notrack=true")
		}
		if rule.Position != "?" {
			url_str = append(url_str, "&position=", rule.Position)
		}
		if rule.Logprefix != "" {
			url_str = append(url_str, "&log-prefix=", rule.Logprefix)
		}
	} else {
		url_str = url_str_1
	}
	
	req, err := client.newRequest(method, strings.Join(url_str, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))

	if resp.StatusCode == 200 {
		return true, nil
	}
	if resp.StatusCode == 404 {
		return false, nil
	}
	if resp.StatusCode == 409 {
		return false, errors.New("Conflict with position")
	}
	return false, errors.New(string(body))
}

func (client *Client) ChainAPI(chain string, method string) (bool, error) {
	url_str := []string{"/chain/filter/", chain, "/"}
	req, err := client.newRequest(method, strings.Join(url_str, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return false, err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))

	if resp.StatusCode == 200 {
		return true, nil
	}
	if resp.StatusCode == 400 {
		return false, nil
	}
	if resp.StatusCode == 401 {
		return false, errors.New(strings.Join([]string{client.Firewall_IP, ": You are Unauthorized"}, " "))
	}
	return false, errors.New(string(body))
}

func (client *Client) mvChain(old_chain string, new_chain string) error {
	url_str := []string{"/mvchain/filter/", old_chain, "/", new_chain, "/"}
	req, err := client.newRequest("PUT", strings.Join(url_str, ""))
	if err != nil {
        return err
    }
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))
	
	if resp.StatusCode == 200 {
		return nil
	}
	return errors.New(string(body))
}

func (client *Client) save() error {
	req, err := client.newRequest("GET", "/save/")
	if err != nil {
		return err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
	        TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
	    }
	}
	http_client := &http.Client{Transport: tr}
	resp, err := http_client.Do(req)
	if err != nil {
		log.Printf("[ERROR] Error when do Req %s", err)
		return err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %s", resp.StatusCode, string(body))
	if resp.StatusCode != 200 {
		return errors.New(string(body))
	}
	return nil
}
