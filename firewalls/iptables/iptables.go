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
