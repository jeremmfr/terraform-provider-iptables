package iptables

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

const (
	maxLengthProjectName = 30
)

func resourceProject() *schema.Resource {
	return &schema.Resource{
		Create: resourceProjectCreate,
		Read:   resourceProjectRead,
		Update: resourceProjectUpdate,
		Delete: resourceProjectDelete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:     schema.TypeString,
				Required: true,
				ForceNew: true,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(string)
					if len(value) > maxLengthProjectName {
						errors = append(errors, fmt.Errorf(
							"%q cannot be longer than 30 characters", k))
					}

					return
				},
			},
			"cidr_blocks": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"position": {
				Type:     schema.TypeInt,
				Optional: true,
				Default:  0,
				ValidateFunc: func(v interface{}, k string) (ws []string, errors []error) {
					value := v.(int)
					if value < 0 {
						errors = append(errors, fmt.Errorf(
							"%q cannot be lower than 0: %d", k, value))
					}

					return
				},
			},
		},
	}
}

func resourceProjectCreate(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	checkExists, err := client.chainAPIV4(d.Get("name").(string), httpGet)
	if err != nil {
		return fmt.Errorf("check if project %s exist failed : %s", d.Get("name"), err)
	}
	if !checkExists {
		create, err := client.chainAPIV4(d.Get("name").(string), httpPut)
		if !create || err != nil {
			return fmt.Errorf("create project %s failed : %s", d.Get("name"), err)
		}
	} else {
		return fmt.Errorf("project %s already exist", d.Get("name"))
	}
	d.SetId(d.Get("name").(string) + "!")

	return resourceProjectUpdate(d, m)
}

func resourceProjectRead(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)

	checkExists, err := client.chainAPIV4(d.Get("name").(string), httpGet)
	if err != nil {
		return fmt.Errorf("read project %s failed : %s", d.Get("name"), err)
	}
	if !checkExists {
		d.SetId("")

		return nil
	}
	if d.Get("position").(int) != 0 {
		routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(d.Get("position").(int)))}, "")
		checkExists, err := client.chainAPIV4(routerChainName, httpGet)
		if err != nil {
			return fmt.Errorf("read chain router_chain_pos %s failed : %s", routerChainName, err)
		}
		if !checkExists {
			tfErr := d.Set("position", 0)
			if tfErr != nil {
				panic(tfErr)
			}
		}
		routerChainPos, err := insertPosrouter(absolute(d.Get("position").(int)), httpGet, m)
		if err != nil {
			return fmt.Errorf("read position %d in router_chain failed : %s", d.Get("position").(int), err)
		}
		if !routerChainPos {
			tfErr := d.Set("position", absolute(d.Get("position").(int))*-1)
			if tfErr != nil {
				panic(tfErr)
			}
		} else {
			tfErr := d.Set("position", absolute(d.Get("position").(int)))
			if tfErr != nil {
				panic(tfErr)
			}
		}
	}
	var listCIDRSet []interface{}
	for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
		status, err := cidrForProject(cidr.(string), absolute(d.Get("position").(int)), httpGet, d, m)
		if err == nil && status {
			listCIDRSet = append(listCIDRSet, cidr.(string))
		}
	}
	tfErr := d.Set("cidr_blocks", listCIDRSet)
	if tfErr != nil {
		panic(tfErr)
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceProjectUpdate(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	positionChange := false
	var oPos, nPos interface{}
	oPos = 0
	if d.HasChange("position") {
		positionChange = true
		oPos, nPos = d.GetChange("position")
		if oPos.(int) != 0 {
			for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
				err := checkCIDRBlocksString(cidr.(string), ipv4ver)
				if err != nil {
					tfErr := d.Set("position", oPos.(int))
					if tfErr != nil {
						panic(tfErr)
					}

					return err
				}
				_, err = cidrForProject(cidr.(string), 0, httpPut, d, m)
				if err != nil {
					tfErr := d.Set("position", oPos.(int))
					if tfErr != nil {
						panic(tfErr)
					}

					return err
				}
			}
			rulePosDel, err := insertPosrouter(absolute(oPos.(int)), httpDel, m)
			if !rulePosDel || err != nil {
				tfErr := d.Set("position", oPos.(int))
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("delete rule for position %d failed : %s", oPos.(int), err)
			}
			routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(oPos.(int)))}, "")
			routeChainDel, err := client.chainAPIV4(routerChainName, httpDel)
			if !routeChainDel || err != nil {
				tfErr := d.Set("position", oPos.(int))
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("delete chain %s failed : %s", routerChainName, err)
			}
			tfErr := d.Set("position", 0)
			if tfErr != nil {
				panic(tfErr)
			}
		}
		if nPos.(int) > 0 {
			routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(nPos.(int))}, "")
			checkExists, err := client.chainAPIV4(routerChainName, httpGet)
			if err != nil {
				tfErr := d.Set("position", 0)
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("check if chain %s exist failed : %s", routerChainName, err)
			}
			if checkExists {
				tfErr := d.Set("position", 0)
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("position %d already used", nPos.(int))
			}
			create, err := client.chainAPIV4(routerChainName, httpPut)
			if !create || err != nil {
				tfErr := d.Set("position", 0)
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("create chain %s for position : %s", routerChainName, err)
			}
			createPos, err := insertPosrouter(nPos.(int), httpPut, m)
			if !createPos || err != nil {
				removeChainPos, err2 := client.chainAPIV4(routerChainName, httpDel)
				if !removeChainPos || err2 != nil {
					tfErr := d.Set("position", 0)
					if tfErr != nil {
						panic(tfErr)
					}

					return fmt.Errorf("insert position in router_chain failed %s and "+
						"error for delete router_chain_pos %s (please delete manually) : %s",
						err, routerChainName, err2)
				}
				tfErr := d.Set("position", 0)
				if tfErr != nil {
					panic(tfErr)
				}

				return fmt.Errorf("insert position in router_chain failed : %s", err)
			}
			if !d.HasChange("cidr_blocks") {
				for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
					err := checkCIDRBlocksString(cidr.(string), ipv4ver)
					if err != nil {
						return err
					}
					_, err = cidrForProject(cidr.(string), nPos.(int), httpPut, d, m)
					if err != nil {
						return err
					}
				}
				err := client.saveV4()
				if err != nil {
					return fmt.Errorf("iptables save failed : %s", err)
				}
			}
		}
	} else {
		nPos = d.Get("position")
	}
	if d.HasChange("cidr_blocks") {
		oldCIDR, newCIDR := d.GetChange("cidr_blocks")
		cidrListRemove := computeRemove(oldCIDR.(*schema.Set).List(), newCIDR.(*schema.Set).List())
		for _, cidr := range cidrListRemove {
			_, err := cidrForProject(cidr.(string), nPos.(int), httpDel, d, m)
			if err != nil {
				return err
			}
		}
		for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
			err := checkCIDRBlocksString(cidr.(string), ipv4ver)
			if err != nil {
				return err
			}
			_, err = cidrForProject(cidr.(string), nPos.(int), httpPut, d, m)
			if err != nil {
				return err
			}
		}
		err := client.saveV4()
		if err != nil {
			return fmt.Errorf("iptables save failed : %s", err)
		}
	}
	if positionChange {
		if d.HasChange("cidr_blocks") && oPos.(int) == 0 && nPos.(int) > 0 {
			oldCIDR, _ := d.GetChange("cidr_blocks")
			for _, cidr := range oldCIDR.(*schema.Set).List() {
				_, err := cidrForProject(cidr.(string), 0, httpDel, d, m)
				if err != nil {
					return err
				}
			}
		}
		if nPos.(int) > 0 {
			for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
				_, err := cidrForProject(cidr.(string), 0, httpDel, d, m)
				if err != nil {
					return err
				}
			}
		}
	}
	tfErr := d.Set("position", nPos.(int))
	if tfErr != nil {
		panic(tfErr)
	}

	return nil
}

func resourceProjectDelete(d *schema.ResourceData, m interface{}) error {
	client := m.(*Client)
	cidrListRemove := d.Get("cidr_blocks").(*schema.Set).List()
	for _, cidr := range cidrListRemove {
		_, err := cidrForProject(cidr.(string), absolute(d.Get("position").(int)), httpDel, d, m)
		if err != nil {
			return err
		}
	}

	chainDeleted, err := client.chainAPIV4(d.Get("name").(string), httpDel)
	if !chainDeleted || err != nil {
		return fmt.Errorf("delete project %s failed : %s", d.Get("name"), err)
	}
	if d.Get("position").(int) != 0 {
		rulePosDel, err := insertPosrouter(absolute(d.Get("position").(int)), httpDel, m)
		if !rulePosDel || err != nil {
			return fmt.Errorf("delete rule for position %d failed : %s", d.Get("position").(int), err)
		}
		routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(d.Get("position").(int)))}, "")
		routeChainDel, err := client.chainAPIV4(routerChainName, httpDel)
		if !routeChainDel || err != nil {
			return fmt.Errorf("delete chain %s failed : %s", routerChainName, err)
		}
	}
	d.SetId("")
	err = client.saveV4()
	if err != nil {
		return fmt.Errorf("iptables save failed : %s", err)
	}

	return nil
}

func cidrForProject(cidr string, position int, method string, d *schema.ResourceData, m interface{}) (bool, error) {
	routerChain := "router_chain"
	if position != 0 {
		routerChain = strings.Join([]string{"router_chain_pos", strconv.Itoa(position)}, "")
	}
	// Route for source cidr
	client := m.(*Client)
	route := Rule{
		Action:   d.Get("name").(string),
		Chain:    routerChain,
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    strings.ReplaceAll(cidr, "/", "_"),
		IPDst:    "0.0.0.0_0",
		Sports:   "0",
		Dports:   "0",
	}

	// Apply on table filter route for source cidr

	routeexists, err := client.rulesAPIV4(route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for cidr %s failed : %s", cidr, err)
	}
	if !routeexists && method == httpPut {
		routeCIDR, err := client.rulesAPIV4(route, httpPut)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("create rules source for cidr %s failed : %s", cidr, err)
		}
	}
	if routeexists && method == httpDel {
		routeCIDR, err := client.rulesAPIV4(route, httpDel)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("delete rules source for cidr %s failed : %s", cidr, err)
		}
	}
	if !routeexists && method == httpGet {
		return routeexists, nil
	}

	// Route for destination cidr
	route = Rule{
		Action:   d.Get("name").(string),
		Chain:    routerChain,
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    "0.0.0.0_0",
		IPDst:    strings.ReplaceAll(cidr, "/", "_"),
		Sports:   "0",
		Dports:   "0",
	}
	// Apply on table filter route for destination cidr
	routeexists, err = client.rulesAPIV4(route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for cidr %s failed : %s", cidr, err)
	}
	if !routeexists && method == httpPut {
		routeCIDR, err := client.rulesAPIV4(route, httpPut)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("create rules destination for cidr %s failed : %s", cidr, err)
		}
	}
	if routeexists && method == httpDel {
		routeCIDR, err := client.rulesAPIV4(route, httpDel)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("delete rules destination for cidr %s failed : %s", cidr, err)
		}
	}
	if !routeexists && method == httpGet {
		return routeexists, nil
	}

	return true, nil
}

func insertPosrouter(position int, method string, m interface{}) (bool, error) {
	client := m.(*Client)
	routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(position)}, "")
	route := Rule{
		Action:   routerChainName,
		Chain:    "router_chain",
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    "0.0.0.0_0",
		IPDst:    "0.0.0.0_0",
		Sports:   "0",
		Dports:   "0",
		Position: strconv.Itoa(position),
	}
	routeNoPos := Rule{
		Action:   routerChainName,
		Chain:    "router_chain",
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    "0.0.0.0_0",
		IPDst:    "0.0.0.0_0",
		Sports:   "0",
		Dports:   "0",
	}
	routeexists, err := client.rulesAPIV4(route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for project position %d failed : %s", position, err)
	}
	if !routeexists && method == httpPut {
		routePut, err := client.rulesAPIV4(route, httpPut)
		if !routePut || err != nil {
			return routeexists, fmt.Errorf("create rules for project position %d failed : %s", position, err)
		}
	}
	if method == httpDel {
		if routeexists {
			routeDel, err := client.rulesAPIV4(route, httpDel)
			if !routeDel || err != nil {
				return routeexists, fmt.Errorf("delete rules for project position %d failed : %s", position, err)
			}
		} else {
			routeexistsNoPos, err := client.rulesAPIV4(routeNoPos, httpGet)
			if err != nil {
				return routeexistsNoPos, fmt.Errorf("check rules for project position "+
					"with bad position %d failed : %s", position, err)
			}
			if routeexistsNoPos {
				routeDel, err := client.rulesAPIV4(routeNoPos, httpDel)
				if !routeDel || err != nil {
					return routeexistsNoPos, fmt.Errorf("delete rules for project position "+
						"with bad position %d failed : %s", position, err)
				}
			}
		}
	}
	if !routeexists && method == httpGet {
		return routeexists, nil
	}

	return true, nil
}
