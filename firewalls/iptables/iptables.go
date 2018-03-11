package iptables

import (
	"fmt"
	ipt "github.com/coreos/go-iptables/iptables"
	"github.com/xaionaro-go/go-ipset/ipset"
	"github.com/xaionaro-go/networkControl"
	"os"
	"strconv"
	"strings"
)

type iptables struct {
	iptables *ipt.IPTables
}

func NewFirewall() networkControl.FirewallI {
	newIPT, err := ipt.New()
	if err != nil {
		panic(err)
	}
	return &iptables{iptables: newIPT}
}

func (fw iptables) InquireSecurityLevel(ifName string) int {
	setNames, err := ipset.Names()
	if err != nil {
		panic(err)
	}

	// TODO: sort setNames numberically before the "for" below

	// Searching for IFACES.SECURITY_LEVEL.###
	for _, setName := range setNames {
		if !strings.HasPrefix(setName, "IFACES.SECURITY_LEVEL.") {
			continue
		}

		setNameWords := strings.Split(setName, ".")
		securityLevel, err := strconv.Atoi(setNameWords[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid security level value \"%v\" (in ipset name: %v): %v", setNameWords[2], setName, err.Error())
			continue
		}

		rows, err := ipset.List(setName)
		if err != nil {
			panic(err)
		}

		for _, row := range rows {
			words := strings.Split(row, ",")
			if words[1] == ifName {
				return securityLevel
			}
		}
	}

	return 0
}

func (fw iptables) getACLsNames() (result []string) {
	setNames, err := ipset.Names()
	if err != nil {
		panic(err)
	}
	// Searching for ACL.IN.###
	for _, setName := range setNames {
		setNameWords := strings.Split(setName, ".")
		if setNameWords[0] != "ACL" {
			continue
		}
		if len(setNameWords) != 3 {
			panic(fmt.Errorf("Internal error: %v", setNameWords))
		}
		result = append(result, setNameWords[2])
	}

	return
}
func (fw iptables) inquireACL(aclName string) (result networkControl.ACL) {

	// Getting VLANs of the ACL

	setName := "ACL.IN."+aclName
	setRows, err := ipset.List(setName)
	if err != nil {
		panic(err)
	}

	for _, setRow := range setRows {
		words := strings.Split(setRow, ",")
		if words[0] != "0.0.0.0/0" {
			panic("Internal error. words[0] == \""+words[0]+"\"")
		}
		ifName := words[1]
		result.VLANNames = append(result.VLANNames, ifName)
	}

	fw.iptables.List("filter", "ACL.IN."+aclName)

	panic("Not implemented, yet")

	return
}
func (fw iptables) InquireACLs() (result networkControl.ACLs) {
	aclNames := fw.getACLsNames()
	for _, aclName := range aclNames {
		acl := fw.inquireACL(aclName)
		result = append(result, &acl)
	}

	return
}
func (fw iptables) InquireSNATs() (result networkControl.SNATs) {
	panic("Not implemented, yet")
	return
}
func (fw iptables) InquireDNATs() (result networkControl.DNATs) {
	panic("Not implemented, yet")
	return
}

