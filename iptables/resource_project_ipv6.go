package iptables

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func resourceProjectIPv6() *schema.Resource {
	return &schema.Resource{
		CreateContext: resourceProjectIPv6Create,
		ReadContext:   resourceProjectIPv6Read,
		UpdateContext: resourceProjectIPv6Update,
		DeleteContext: resourceProjectIPv6Delete,
		Schema: map[string]*schema.Schema{
			"name": {
				Type:         schema.TypeString,
				Required:     true,
				ForceNew:     true,
				ValidateFunc: validation.StringLenBetween(1, maxLengthProjectName),
			},
			"cidr_blocks": {
				Type:     schema.TypeSet,
				Required: true,
				Elem:     &schema.Schema{Type: schema.TypeString},
			},
			"position": {
				Type:         schema.TypeInt,
				Optional:     true,
				ForceNew:     true,
				Default:      0,
				ValidateFunc: validation.IntAtLeast(0),
			},
		},
	}
}

func resourceProjectIPv6Create(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)

	if !client.IPv6 {
		return diag.FromErr(fmt.Errorf("ipv6 not enable on provider"))
	}
	checkExists, err := client.chainAPIV6(ctx, d.Get("name").(string), httpGet)
	if err != nil {
		return diag.FromErr(fmt.Errorf("check if project %s exist failed : %w", d.Get("name"), err))
	}
	if !checkExists {
		create, err := client.chainAPIV6(ctx, d.Get("name").(string), httpPut)
		if !create || err != nil {
			return diag.FromErr(fmt.Errorf("create project %s failed : %w", d.Get("name"), err))
		}
	} else {
		return diag.FromErr(fmt.Errorf("project %s already exist", d.Get("name")))
	}
	d.SetId(d.Get("name").(string) + "!")

	return resourceProjectIPv6Update(ctx, d, m)
}

func resourceProjectIPv6Read(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)

	if !client.IPv6 {
		return diag.FromErr(fmt.Errorf("ipv6 not enable on provider"))
	}

	checkExists, err := client.chainAPIV6(ctx, d.Get("name").(string), httpGet)
	if err != nil {
		return diag.FromErr(fmt.Errorf("read project %s failed : %w", d.Get("name"), err))
	}
	if !checkExists {
		d.SetId("")

		return nil
	}
	if d.Get("position").(int) != 0 {
		routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(d.Get("position").(int)))}, "")
		checkExists, err := client.chainAPIV6(ctx, routerChainName, httpGet)
		if err != nil {
			return diag.FromErr(fmt.Errorf("read chain router_chain_pos %s failed : %w", routerChainName, err))
		}
		if !checkExists {
			if tfErr := d.Set("position", 0); tfErr != nil {
				panic(tfErr)
			}
		}
		routerChainPos, err := insertPosrouterV6(ctx, absolute(d.Get("position").(int)), httpGet, m)
		if err != nil {
			return diag.FromErr(fmt.Errorf("read position %d in router_chain failed : %w", d.Get("position").(int), err))
		}
		if !routerChainPos {
			if tfErr := d.Set("position", absolute(d.Get("position").(int))*-1); tfErr != nil {
				panic(tfErr)
			}
		} else {
			if tfErr := d.Set("position", absolute(d.Get("position").(int))); tfErr != nil {
				panic(tfErr)
			}
		}
	}

	var listCIDRSet []interface{}
	for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
		status, err := cidrForProjectV6(ctx, cidr.(string), absolute(d.Get("position").(int)), httpGet, d, m)
		if err == nil && status {
			listCIDRSet = append(listCIDRSet, cidr.(string))
		}
	}
	if tfErr := d.Set("cidr_blocks", listCIDRSet); tfErr != nil {
		panic(tfErr)
	}
	d.SetId(d.Get("name").(string) + "!")

	return nil
}

func resourceProjectIPv6Update(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)

	if !client.IPv6 {
		return diag.FromErr(fmt.Errorf("ipv6 not enable on provider"))
	}
	positionChange := false
	var oPos, nPos interface{}
	oPos = 0
	if d.HasChange("position") {
		positionChange = true
		oPos, nPos = d.GetChange("position")
		if oPos.(int) != 0 {
			for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
				if err := checkCIDRBlocksString(cidr.(string), ipv6ver); err != nil {
					if tfErr := d.Set("position", oPos.(int)); tfErr != nil {
						panic(tfErr)
					}

					return diag.FromErr(err)
				}
				if _, err := cidrForProjectV6(ctx, cidr.(string), 0, httpPut, d, m); err != nil {
					if tfErr := d.Set("position", oPos.(int)); tfErr != nil {
						panic(tfErr)
					}

					return diag.FromErr(err)
				}
			}
			rulePosDel, err := insertPosrouterV6(ctx, absolute(oPos.(int)), httpDel, m)
			if !rulePosDel || err != nil {
				if tfErr := d.Set("position", oPos.(int)); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("delete rule for position %d failed : %w", oPos.(int), err))
			}
			routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(oPos.(int)))}, "")
			routeChainDel, err := client.chainAPIV6(ctx, routerChainName, httpDel)
			if !routeChainDel || err != nil {
				if tfErr := d.Set("position", oPos.(int)); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("delete chain %s failed : %w", routerChainName, err))
			}
			if tfErr := d.Set("position", 0); tfErr != nil {
				panic(tfErr)
			}
		}
		if nPos.(int) > 0 {
			routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(nPos.(int))}, "")
			checkExists, err := client.chainAPIV6(ctx, routerChainName, httpGet)
			if err != nil {
				if tfErr := d.Set("position", 0); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("check if chain %s exist failed : %w", routerChainName, err))
			}
			if checkExists {
				if tfErr := d.Set("position", 0); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("position %d already used", nPos.(int)))
			}
			create, err := client.chainAPIV6(ctx, routerChainName, httpPut)
			if !create || err != nil {
				if tfErr := d.Set("position", 0); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("create chain %s for position : %w", routerChainName, err))
			}
			createPos, err := insertPosrouterV6(ctx, nPos.(int), httpPut, m)
			if !createPos || err != nil {
				removeChainPos, err2 := client.chainAPIV6(ctx, routerChainName, httpDel)
				if !removeChainPos || err2 != nil {
					if tfErr := d.Set("position", 0); tfErr != nil {
						panic(tfErr)
					}

					return diag.FromErr(fmt.Errorf("insert position in router_chain failed %s and "+
						"error for delete router_chain_pos %s (please delete manually) : %s",
						err, routerChainName, err2))
				}
				if tfErr := d.Set("position", 0); tfErr != nil {
					panic(tfErr)
				}

				return diag.FromErr(fmt.Errorf("insert position in router_chain failed : %w", err))
			}
			if !d.HasChange("cidr_blocks") {
				for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
					if err := checkCIDRBlocksString(cidr.(string), ipv6ver); err != nil {
						return diag.FromErr(err)
					}
					if _, err = cidrForProjectV6(ctx, cidr.(string), nPos.(int), httpPut, d, m); err != nil {
						return diag.FromErr(err)
					}
				}

				if err := client.saveV6(ctx); err != nil {
					return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
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
			if _, err := cidrForProjectV6(ctx, cidr.(string), nPos.(int), httpDel, d, m); err != nil {
				return diag.FromErr(err)
			}
		}
		for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
			if err := checkCIDRBlocksString(cidr.(string), ipv6ver); err != nil {
				return diag.FromErr(err)
			}
			if _, err := cidrForProjectV6(ctx, cidr.(string), nPos.(int), httpPut, d, m); err != nil {
				return diag.FromErr(err)
			}
		}

		if err := client.saveV6(ctx); err != nil {
			return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
		}
	}
	if positionChange {
		if d.HasChange("cidr_blocks") && oPos.(int) == 0 && nPos.(int) > 0 {
			oldCIDR, _ := d.GetChange("cidr_blocks")
			for _, cidr := range oldCIDR.(*schema.Set).List() {
				if _, err := cidrForProjectV6(ctx, cidr.(string), 0, httpDel, d, m); err != nil {
					return diag.FromErr(err)
				}
			}
		}
		if nPos.(int) > 0 {
			for _, cidr := range d.Get("cidr_blocks").(*schema.Set).List() {
				if _, err := cidrForProjectV6(ctx, cidr.(string), 0, httpDel, d, m); err != nil {
					return diag.FromErr(err)
				}
			}
		}
	}
	if tfErr := d.Set("position", nPos.(int)); tfErr != nil {
		panic(tfErr)
	}

	return nil
}

func resourceProjectIPv6Delete(ctx context.Context, d *schema.ResourceData, m interface{}) diag.Diagnostics {
	client := m.(*Client)

	if !client.IPv6 {
		return diag.FromErr(fmt.Errorf("ipv6 not enable on provider"))
	}

	cidrListRemove := d.Get("cidr_blocks").(*schema.Set).List()
	for _, cidr := range cidrListRemove {
		if _, err := cidrForProjectV6(ctx, cidr.(string), absolute(d.Get("position").(int)), httpDel, d, m); err != nil {
			return diag.FromErr(err)
		}
	}
	if chainDeleted, err := client.chainAPIV6(ctx, d.Get("name").(string), httpDel); !chainDeleted || err != nil {
		return diag.FromErr(fmt.Errorf("delete project %s failed : %w", d.Get("name"), err))
	}
	if d.Get("position").(int) != 0 {
		rulePosDel, err := insertPosrouterV6(ctx, absolute(d.Get("position").(int)), httpDel, m)
		if !rulePosDel || err != nil {
			return diag.FromErr(fmt.Errorf("delete rule for position %d failed : %w", d.Get("position").(int), err))
		}
		routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(d.Get("position").(int)))}, "")
		routeChainDel, err := client.chainAPIV6(ctx, routerChainName, httpDel)
		if !routeChainDel || err != nil {
			return diag.FromErr(fmt.Errorf("delete chain %s failed : %w", routerChainName, err))
		}
	}
	d.SetId("")
	if err := client.saveV6(ctx); err != nil {
		return diag.FromErr(fmt.Errorf("ip6tables save failed : %w", err))
	}

	return nil
}

func cidrForProjectV6(
	ctx context.Context, cidr string, position int, method string, d *schema.ResourceData, m interface{},
) (bool, error) {
	routerChain := "router_chain"
	if position != 0 {
		routerChain = strings.Join([]string{"router_chain_pos", strconv.Itoa(absolute(d.Get("position").(int)))}, "")
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
		IPDst:    "::_0",
		Sports:   "0",
		Dports:   "0",
	}

	// Apply on table filter route for source cidr

	routeexists, err := client.rulesAPIV6(ctx, route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for cidr %s failed : %w", cidr, err)
	}
	if !routeexists && method == httpPut {
		routeCIDR, err := client.rulesAPIV6(ctx, route, httpPut)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("create rules source for cidr %s failed : %w", cidr, err)
		}
	}
	if routeexists && method == httpDel {
		routeCIDR, err := client.rulesAPIV6(ctx, route, httpDel)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("delete rules source for cidr %s failed : %w", cidr, err)
		}
	}
	if routeexists && method == httpGet {
		return routeexists, nil
	}

	// Route for destination cidr
	route = Rule{
		Action:   d.Get("name").(string),
		Chain:    routerChain,
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    "::_0",
		IPDst:    strings.ReplaceAll(cidr, "/", "_"),
		Sports:   "0",
		Dports:   "0",
	}
	// Apply on table filter route for destination cidr
	routeexists, err = client.rulesAPIV6(ctx, route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for cidr %s failed : %w", cidr, err)
	}
	if !routeexists && method == httpPut {
		routeCIDR, err := client.rulesAPIV6(ctx, route, httpPut)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("create rules destination for cidr %s failed : %w", cidr, err)
		}
	}
	if routeexists && method == httpDel {
		routeCIDR, err := client.rulesAPIV6(ctx, route, httpDel)
		if !routeCIDR || err != nil {
			return routeexists, fmt.Errorf("delete rules destination for cidr %s failed : %w", cidr, err)
		}
	}
	if !routeexists && method == httpGet {
		return routeexists, nil
	}

	return true, nil
}

func insertPosrouterV6(ctx context.Context, position int, method string, m interface{}) (bool, error) {
	client := m.(*Client)
	routerChainName := strings.Join([]string{"router_chain_pos", strconv.Itoa(position)}, "")
	route := Rule{
		Action:   routerChainName,
		Chain:    "router_chain",
		Proto:    "all",
		IfaceIn:  "*",
		IfaceOut: "*",
		IPSrc:    "::_0",
		IPDst:    "::_0",
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
		IPSrc:    "::_0",
		IPDst:    "::_0",
		Sports:   "0",
		Dports:   "0",
	}
	routeexists, err := client.rulesAPIV6(ctx, route, httpGet)
	if err != nil {
		return routeexists, fmt.Errorf("check rules for project position %d failed : %w", position, err)
	}
	if !routeexists && method == httpPut {
		routePut, err := client.rulesAPIV6(ctx, route, httpPut)
		if !routePut || err != nil {
			return routeexists, fmt.Errorf("create rules for project position %d failed : %w", position, err)
		}
	}
	if method == httpDel {
		if routeexists {
			routeDel, err := client.rulesAPIV6(ctx, route, httpDel)
			if !routeDel || err != nil {
				return routeexists, fmt.Errorf("delete rules for project position %d failed : %w", position, err)
			}
		} else {
			routeexistsNoPos, err := client.rulesAPIV4(ctx, routeNoPos, httpGet)
			if err != nil {
				return routeexistsNoPos, fmt.Errorf("check rules for project position "+
					"with bad position %d failed: %s", position, err)
			}
			if routeexistsNoPos {
				routeDel, err := client.rulesAPIV4(ctx, routeNoPos, httpDel)
				if !routeDel || err != nil {
					return routeexistsNoPos, fmt.Errorf("delete rules for project position "+
						"with bad position %d failed : %w", position, err)
				}
			}
		}
	}
	if !routeexists && method == httpGet {
		return routeexists, nil
	}

	return true, nil
}
