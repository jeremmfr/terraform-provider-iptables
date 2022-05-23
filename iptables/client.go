package iptables

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"os"
	"strconv"
	"strings"
)

// Client = provider configuration.
type Client struct {
	HTTPS      bool
	Insecure   bool
	IPv6       bool
	Port       int
	FirewallIP string
	Logname    string
	Login      string
	Password   string
	AllowedIPs []interface{}
}

// Rule struc for generate iptables line.
type Rule struct {
	Except    bool
	Fragment  bool
	Notrack   bool
	Action    string
	State     string
	Icmptype  string
	Chain     string
	Proto     string
	IfaceIn   string
	IfaceOut  string
	Iface     string
	IPSrc     string
	IPDst     string
	IPNat     string
	Sports    string
	Dports    string
	Tcpflags1 string
	Tcpflags2 string
	Position  string
	NthEvery  string
	NthPacket string
	Logprefix string
	Tcpmss    string
}

// NewClient configure.
func NewClient(ctx context.Context, c *Config, login, password string) (*Client, error) {
	client := &Client{
		FirewallIP: c.firewallIP,
		Port:       c.firewallPortAPI,
		AllowedIPs: c.allowedIPs,
		HTTPS:      c.https,
		Insecure:   c.insecure,
		Logname:    c.logname,
		Login:      login,
		Password:   password,
		IPv6:       c.ipv6Enable,
	}

	// Allow no default rules
	if os.Getenv("CONFIG_IPTABLES_TERRAFORM_NODEFAULT") == "" {
		checkExistsRouter, err := client.chainAPIV4(ctx, "router_chain", "GET")
		if err != nil {
			return nil, err
		}
		if !checkExistsRouter {
			createChain, err := client.chainAPIV4(ctx, "router_chain", "PUT")
			if !createChain || err != nil {
				return nil, fmt.Errorf("create chain router failed : %w", err)
			}
		}
		//	Add AllowedIPs on TCP Firewal_IP:Port
		for _, cidr := range client.AllowedIPs {
			// raw notrack on Firewal_IP:Port
			acceptAPI := Rule{
				Action:    "CT",
				Chain:     "PREROUTING",
				Proto:     "tcp",
				IfaceIn:   "*",
				IfaceOut:  "*",
				IPSrc:     strings.ReplaceAll(cidr.(string), "/", "_"),
				IPDst:     client.FirewallIP,
				Sports:    "0",
				Dports:    strconv.Itoa(client.Port),
				Tcpflags1: "SYN,RST,ACK,FIN",
				Tcpflags2: "SYN",
				Notrack:   true,
				Position:  "?",
			}
			routeexists, err := client.rawAPIV4(ctx, acceptAPI, "GET")
			if err != nil {
				return nil, fmt.Errorf("check rules (raw) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
			}
			if !routeexists {
				routeCIDR, err := client.rawAPIV4(ctx, acceptAPI, "PUT")
				if !routeCIDR || err != nil {
					return nil, fmt.Errorf("create rules (raw) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
				}
			}

			// ingress on Firewal_IP:Port
			acceptAPI = Rule{
				Action:   "ACCEPT",
				Chain:    "router_chain",
				Proto:    "tcp",
				IfaceIn:  "*",
				IfaceOut: "*",
				IPSrc:    strings.ReplaceAll(cidr.(string), "/", "_"),
				IPDst:    client.FirewallIP,
				Sports:   "0",
				Dports:   strconv.Itoa(client.Port),
				Position: "?",
			}
			routeexists, err = client.rulesAPIV4(ctx, acceptAPI, "GET")
			if err != nil {
				return nil, fmt.Errorf("check rules (ingress) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
			}
			if !routeexists {
				routeCIDR, err := client.rulesAPIV4(ctx, acceptAPI, "PUT")
				if !routeCIDR || err != nil {
					return nil, fmt.Errorf("create rules (ingress) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
				}
			}

			// egress on Firewal_IP:Port
			acceptAPI = Rule{
				Action:   "ACCEPT",
				Chain:    "router_chain",
				Proto:    "tcp",
				IfaceIn:  "*",
				IfaceOut: "*",
				IPSrc:    client.FirewallIP,
				IPDst:    strings.ReplaceAll(cidr.(string), "/", "_"),
				Sports:   strconv.Itoa(client.Port),
				Dports:   "0",
				Position: "?",
			}
			routeexists, err = client.rulesAPIV4(ctx, acceptAPI, "GET")
			if err != nil {
				return nil, fmt.Errorf("check rules (egress) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
			}
			if !routeexists {
				routeCIDR, err := client.rulesAPIV4(ctx, acceptAPI, "PUT")
				if !routeCIDR || err != nil {
					return nil, fmt.Errorf("create rules (egress) allowed IP for API for cidr %s failed : %w", cidr.(string), err)
				}
			}
		}

		// Add rules for default chain
		defaultTable := []string{"INPUT", "FORWARD", "OUTPUT"}
		for _, table := range defaultTable {
			routeDefault := Rule{
				Action:   "router_chain",
				Chain:    table,
				Proto:    "all",
				IfaceIn:  "*",
				IfaceOut: "*",
				IPSrc:    "0.0.0.0_0",
				IPDst:    "0.0.0.0_0",
				Sports:   "0",
				Dports:   "0",
				Position: "?",
			}
			ruleexists, err := client.rulesAPIV4(ctx, routeDefault, "GET")
			if err != nil {
				return nil, fmt.Errorf("check default rules %s failed : %w", table, err)
			}
			if !ruleexists {
				resp, err := client.rulesAPIV4(ctx, routeDefault, "PUT")
				if !resp || err != nil {
					return nil, fmt.Errorf("create default rules %s failed : %w", table, err)
				}
			}
			if !c.noAddDefaultDrop {
				ruleDrop := Rule{
					Action:   "DROP",
					Chain:    table,
					Proto:    "all",
					IfaceIn:  "*",
					IfaceOut: "*",
					IPSrc:    "0.0.0.0_0",
					IPDst:    "0.0.0.0_0",
					Sports:   "0",
					Dports:   "0",
					Position: "?",
				}
				ruleexists, err = client.rulesAPIV4(ctx, ruleDrop, "GET")
				if err != nil {
					return nil, fmt.Errorf("check default rules drop %s failed : %w", table, err)
				}
				if !ruleexists {
					resp, err := client.rulesAPIV4(ctx, ruleDrop, "PUT")
					if !resp || err != nil {
						return nil, fmt.Errorf("create default rules drop %s failed : %w", table, err)
					}
				}
			}
		}
		if c.ipv6Enable {
			checkExistsRouter, err := client.chainAPIV6(ctx, "router_chain", "GET")
			if err != nil {
				return nil, err
			}
			if !checkExistsRouter {
				createChain, err := client.chainAPIV6(ctx, "router_chain", "PUT")
				if !createChain || err != nil {
					return nil, fmt.Errorf("create chain router v6 failed : %w", err)
				}
			}
			for _, table := range defaultTable {
				routeDefault := Rule{
					Action:   "router_chain",
					Chain:    table,
					Proto:    "all",
					IfaceIn:  "*",
					IfaceOut: "*",
					IPSrc:    "::_0",
					IPDst:    "::_0",
					Sports:   "0",
					Dports:   "0",
					Position: "?",
				}
				ruleexists, err := client.rulesAPIV6(ctx, routeDefault, "GET")
				if err != nil {
					return nil, fmt.Errorf("check default rules v6 %s failed : %w", table, err)
				}
				if !ruleexists {
					resp, err := client.rulesAPIV6(ctx, routeDefault, "PUT")
					if !resp || err != nil {
						return nil, fmt.Errorf("create default rules v6 %s failed : %w", table, err)
					}
				}
				if !c.noAddDefaultDrop {
					ruleDrop := Rule{
						Action:   "DROP",
						Chain:    table,
						Proto:    "all",
						IfaceIn:  "*",
						IfaceOut: "*",
						IPSrc:    "::_0",
						IPDst:    "::_0",
						Sports:   "0",
						Dports:   "0",
						Position: "?",
					}
					ruleexists, err = client.rulesAPIV6(ctx, ruleDrop, "GET")
					if err != nil {
						return nil, fmt.Errorf("check default rules drop v6 %s failed : %w", table, err)
					}
					if !ruleexists {
						resp, err := client.rulesAPIV6(ctx, ruleDrop, "PUT")
						if !resp || err != nil {
							return nil, fmt.Errorf("create default rules drop v6 %s failed : %w", table, err)
						}
					}
				}
			}
		}
	}

	return client, nil
}

func (client *Client) newRequest(ctx context.Context, method, uriString string) (*http.Request, error) {
	IP := client.FirewallIP
	port := strconv.Itoa(client.Port)

	matched := strings.Contains(uriString, "?")
	var urLString string
	if matched {
		urLString = "http://" + IP + ":" + port + uriString + "&logname=" + client.Logname
	} else {
		urLString = "http://" + IP + ":" + port + uriString + "?&logname=" + client.Logname
	}
	if client.HTTPS {
		urLString = strings.ReplaceAll(urLString, "http://", "https://")
	}
	req, err := http.NewRequestWithContext(ctx, method, urLString, nil)
	if client.Login != "" && client.Password != "" {
		req.SetBasicAuth(client.Login, client.Password)
	}
	log.Printf("[INFO] New API request: %s %s", method, urLString)
	if err != nil {
		return nil, fmt.Errorf("error during creation of request: %w", err)
	}

	return req, nil
}

func (client *Client) rulesAPI(ctx context.Context, version string, rule Rule, method string) (bool, error) {
	var uriString []string
	if version == "v4" {
		uriString = append(uriString, "/rules/")
	}
	if version == "v6" {
		uriString = append(uriString, "/rules_v6/")
	}
	uriString = append(uriString, rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.IfaceIn, "/", rule.IfaceOut,
		"/", rule.IPSrc, "/", rule.IPDst, "/")
	if (rule.Sports != "0") || (rule.Dports != "0") || (rule.State != "") ||
		(rule.Icmptype != "") || rule.Fragment || (rule.Position != "?") || (rule.Logprefix != "") {
		uriString = append(uriString, "?")
		if rule.Sports != "0" {
			uriString = append(uriString, "&sports=", rule.Sports)
		}
		if rule.Dports != "0" {
			uriString = append(uriString, "&dports=", rule.Dports)
		}
		if rule.State != "" {
			uriString = append(uriString, "&state=", rule.State)
		}
		if rule.Icmptype != "" {
			uriString = append(uriString, "&icmptype=", rule.Icmptype)
		}
		if rule.Fragment {
			uriString = append(uriString, "&fragment=true")
		}
		if rule.Position != "?" {
			uriString = append(uriString, "&position=", rule.Position)
		}
		if rule.Logprefix != "" {
			uriString = append(uriString, "&log-prefix=", rule.Logprefix)
		}
	}

	req, err := client.newRequest(ctx, method, strings.Join(uriString, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error when do request: %s", err)

		return false, fmt.Errorf("error when do request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %d %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode == http.StatusConflict {
		return false, errors.New("conflict with position")
	}

	return false, errors.New(string(body))
}

func (client *Client) natAPI(ctx context.Context, version string, rule Rule, method string) (bool, error) {
	var uriString []string
	if version == "v4" {
		uriString = append(uriString, "/nat/")
	}
	if version == "v6" {
		uriString = append(uriString, "/nat_v6/")
	}
	uriString = append(uriString, rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.Iface, "/",
		rule.IPSrc, "/", rule.IPDst, "/", rule.IPNat, "/")

	if (rule.Dports != "0") || (rule.Position != "?") || (rule.NthEvery != "") || rule.Except {
		uriString = append(uriString, "?")
		if rule.Dports != "0" {
			uriString = append(uriString, "&dport=", rule.Dports)
		}
		if rule.Position != "?" {
			uriString = append(uriString, "&position=", rule.Position)
		}
		if rule.NthEvery != "" {
			uriString = append(uriString, "&nth_every=", rule.NthEvery, "&nth_packet=", rule.NthPacket)
		}
		if rule.Except {
			uriString = append(uriString, "&except=true")
		}
	}

	req, err := client.newRequest(ctx, method, strings.Join(uriString, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error when do request: %s", err)

		return false, fmt.Errorf("error when do request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %d %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode == http.StatusConflict {
		return false, errors.New("conflict with position")
	}

	return false, errors.New(string(body))
}

func (client *Client) rawAPI(ctx context.Context, version string, rule Rule, method string) (bool, error) {
	var uriString []string
	if version == "v4" {
		uriString = append(uriString, "/raw/")
	}
	if version == "v6" {
		uriString = append(uriString, "/raw_v6/")
	}
	uriString = append(uriString, rule.Action, "/", rule.Chain, "/", rule.Proto, "/", rule.IfaceIn, "/",
		rule.IfaceOut, "/", rule.IPSrc, "/", rule.IPDst, "/")
	if (rule.Sports != "0") || (rule.Dports != "0") || (rule.Tcpflags1 != "") || (rule.Tcpflags2 != "") ||
		rule.Notrack || (rule.Position != "?") || (rule.Logprefix != "") || (rule.Tcpmss != "") {
		uriString = append(uriString, "?")
		if rule.Sports != "0" {
			uriString = append(uriString, "&sports=", rule.Sports)
		}
		if rule.Dports != "0" {
			uriString = append(uriString, "&dports=", rule.Dports)
		}
		if (rule.Tcpflags1 != "") && (rule.Tcpflags2 != "") {
			uriString = append(uriString, "&tcpflag1=", rule.Tcpflags1, "&tcpflag2=", rule.Tcpflags2)
		}
		if rule.Notrack {
			uriString = append(uriString, "&notrack=true")
		}
		if rule.Position != "?" {
			uriString = append(uriString, "&position=", rule.Position)
		}
		if rule.Logprefix != "" {
			uriString = append(uriString, "&log-prefix=", rule.Logprefix)
		}
		if rule.Tcpmss != "" {
			uriString = append(uriString, "&tcpmss=", rule.Tcpmss)
		}
	}

	req, err := client.newRequest(ctx, method, strings.Join(uriString, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error when do request: %s", err)

		return false, fmt.Errorf("error when do request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %d %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusNotFound {
		return false, nil
	}
	if resp.StatusCode == http.StatusConflict {
		return false, errors.New("conflict with position")
	}

	return false, errors.New(string(body))
}

func (client *Client) chainAPI(ctx context.Context, version, chain, method string) (bool, error) {
	var uriString []string
	if version == "v4" {
		uriString = append(uriString, "/chain/filter/")
	}
	if version == "v6" {
		uriString = append(uriString, "/chain_v6/filter/")
	}
	uriString = append(uriString, chain, "/")

	req, err := client.newRequest(ctx, method, strings.Join(uriString, ""))
	if err != nil {
		return false, err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error when do request: %s", err)

		return false, fmt.Errorf("error when do request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %d %s", resp.StatusCode, string(body))

	if resp.StatusCode == http.StatusOK {
		return true, nil
	}
	if resp.StatusCode == http.StatusBadRequest {
		return false, nil
	}
	if resp.StatusCode == http.StatusUnauthorized {
		return false, errors.New(strings.Join([]string{client.FirewallIP, ": You are Unauthorized"}, " "))
	}

	return false, errors.New(string(body))
}

func (client *Client) save(ctx context.Context, version string) error {
	var uriString []string
	if version == "v4" {
		uriString = append(uriString, "/save/")
	}
	if version == "v6" {
		uriString = append(uriString, "/save_v6/")
	}

	req, err := client.newRequest(ctx, "GET", strings.Join(uriString, ""))
	if err != nil {
		return err
	}
	tr := &http.Transport{
		DisableKeepAlives: true,
	}
	if client.Insecure {
		tr = &http.Transport{
			TLSClientConfig:   &tls.Config{InsecureSkipVerify: true},
			DisableKeepAlives: true,
		}
	}
	httpClient := &http.Client{Transport: tr}
	resp, err := httpClient.Do(req)
	if err != nil {
		log.Printf("error when do request: %s", err)

		return fmt.Errorf("error when do request: %w", err)
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)
	log.Printf("[INFO] Response API request %d %s", resp.StatusCode, string(body))
	if resp.StatusCode != http.StatusOK {
		return errors.New(string(body))
	}

	return nil
}

func (client *Client) chainAPIV4(ctx context.Context, chain, method string) (bool, error) {
	return client.chainAPI(ctx, "v4", chain, method)
}

func (client *Client) rulesAPIV4(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.rulesAPI(ctx, "v4", rule, method)
}

func (client *Client) natAPIV4(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.natAPI(ctx, "v4", rule, method)
}

func (client *Client) rawAPIV4(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.rawAPI(ctx, "v4", rule, method)
}

func (client *Client) saveV4(ctx context.Context) error {
	return client.save(ctx, "v4")
}

func (client *Client) chainAPIV6(ctx context.Context, chain, method string) (bool, error) {
	return client.chainAPI(ctx, "v6", chain, method)
}

func (client *Client) rulesAPIV6(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.rulesAPI(ctx, "v6", rule, method)
}

func (client *Client) natAPIV6(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.natAPI(ctx, "v6", rule, method)
}

func (client *Client) rawAPIV6(ctx context.Context, rule Rule, method string) (bool, error) {
	return client.rawAPI(ctx, "v6", rule, method)
}

func (client *Client) saveV6(ctx context.Context) error {
	return client.save(ctx, "v6")
}
