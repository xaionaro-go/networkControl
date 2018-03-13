package iptables

import (
	"encoding/json"
	"errors"
	"fmt"
	ipt "github.com/coreos/go-iptables/iptables"
	"github.com/xaionaro-go/go-ipset/ipset"
	"github.com/xaionaro-go/networkControl"
	"net"
	"os"
	"strconv"
	"strings"
)

var (
	errNotImplemented = errors.New("not implemented (yet?)")
)

type iptables struct {
	networkControl.FirewallBase
	iptables              *ipt.IPTables
	isSameSecurityTraffic bool
}

func NewFirewall(host networkControl.HostI) networkControl.FirewallI {
	newIPT, err := ipt.New()
	if err != nil {
		panic(err)
	}

	fw := &iptables{
		iptables: newIPT,
	}

	fw.SetHost(host)

	fw.iptables.NewChain("filter", "ACLs")
	fw.iptables.NewChain("filter", "SECURITY_LEVELs")
	fw.iptables.NewChain("nat", "SNATs")
	fw.iptables.NewChain("nat", "DNATs")

	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "ACLs")
	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "SECURITY_LEVELs")
	fw.iptables.AppendUnique("nat", "PREROUTING", "-j", "DNATs")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-j", "SNATs")

	return fw
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
			if len(row) == 0 || strings.HasPrefix(row, " ") {
				continue
			}
			words := strings.Split(row, ",")
			if len(words) < 2 {
				fw.LogPanic(fmt.Errorf("len(words) < 2"), setName, words)
			}
			if words[1] == ifName {
				return securityLevel
			}
		}
	}

	return 0
}

func (fw *iptables) createSecurityLevelRules() error {
	setNames, err := ipset.Names()
	if err != nil {
		panic(err)
	}

	// Searching for IFACES.SECURITY_LEVEL.###
	securityLevels := []int{}
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

		securityLevels = append(securityLevels, securityLevel)
	}

	for _, securityLevelA := range securityLevels {

		setName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevelA)
		chainName := setName

		minSecurityLevelB := -1
		for _, securityLevelB := range securityLevels {
			if securityLevelA >= securityLevelB {
				continue
			}
			if securityLevelB < minSecurityLevelB {
				minSecurityLevelB = securityLevelB
			}
		}

		setNameB := "IFACES.SECURITY_LEVEL." + strconv.Itoa(minSecurityLevelB)
		chainNameB := setNameB
		fw.iptables.AppendUnique("filter", chainName, "-j", chainNameB)

		if fw.isSameSecurityTraffic {
			fw.iptables.AppendUnique("filter", chainName, "-m", "set", "--match-set", setName, "dst,dst", "-j", "ACCEPT")
		} else {
			fw.iptables.AppendUnique("filter", chainName, "-m", "set", "--match-set", setNameB, "dst,dst", "-j", "ACCEPT")
		}

		fw.iptables.AppendUnique("filter", "SECURITY_LEVELs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
	}

	return nil
}

func (fw *iptables) addSecurityLevel(securityLevel int) error {
	setName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevel)
	_, err := ipset.New(setName, "hash:net,iface", &ipset.Params{})
	if err != nil {
		fw.LogError(err)
		return err
	}

	return fw.createSecurityLevelRules()
}

func (fw *iptables) SetSecurityLevel(ifName string, securityLevel int) error {
	setName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevel)

	// Remembering the old security level set name

	oldSecurityLevel := fw.InquireSecurityLevel(ifName)
	oldSetName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(oldSecurityLevel)

	// Create the security level if not exists

	fw.addSecurityLevel(securityLevel)

	// Adding to the new security level

	err := ipset.Add(setName, "0.0.0.0/0,"+ifName, 0)
	if err != nil {
		fw.LogError(err)
		return err
	}

	// Removing from the old security level

	ipset.Del(oldSetName, "0.0.0.0/0,"+ifName)

	return nil
}

func (fw iptables) IfNameToIPTIfName(ifName string) string {
	return fw.GetHost().IfNameToHostIfName(ifName)
}

func (fw iptables) getACLsNames() (result []string) {
	setNames, err := ipset.Names()
	if err != nil {
		panic(err)
	}
	// Searching for ACL.IN.###
	for _, setName := range setNames {
		if len(setName) == 0 {
			continue
		}

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
	result.Name = aclName

	// Getting VLANs of the ACL

	setName := "ACL.IN." + aclName
	setRows, err := ipset.List(setName)
	if err != nil {
		panic(err)
	}

	for _, setRow := range setRows {
		if len(setRow) == 0 {
			continue
		}

		words := strings.Split(setRow, ",")
		if words[0] != "0.0.0.0/0" {
			panic("Internal error. words[0] == \"" + words[0] + "\"")
		}
		ifName := words[1]
		result.VLANNames = append(result.VLANNames, ifName)
	}

	// Getting rules of the ACL

	chainName := "ACL.IN."+aclName

	fw.iptables.NewChain("filter", chainName) // creating the chain if not exists (could happened on a dirty work before)
	rules, err := fw.iptables.List("filter", chainName)
	if err != nil {
		panic(err)
	}

	for _, rule := range rules {
		if strings.HasPrefix(rule, "-N ") {
			continue
		}
		if !strings.HasPrefix(rule, "-A "+chainName+" ") {
			panic(fmt.Errorf("Unexpected input: %v", rule))
		}
		rule = strings.Replace(rule, "-A "+chainName+" ", "", 1)
		result.Rules = append(result.Rules, parseACLRule(rule))
	}

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
	ruleStrings, err := fw.iptables.List("nat", "SNATs")
	if err != nil {
		panic(err)
	}
	for _, ruleString := range ruleStrings {
		words := strings.Split(ruleString, " ")
		if words[0] == "-N" {
			break
		}
		snat := networkControl.SNAT{}
		source := networkControl.SNATSource{}
		for len(words) > 0 {
			switch words[0] {
			case "-m":
				words = words[2:]

			case "-s":
				var err error
				source.IPNet, err = networkControl.IPNetFromCIDRString(words[1])
				if err != nil {
					panic(err)
				}
				words = words[2:]

			case "--comment":
				snatComment := snatCommentT{}
				err := json.Unmarshal([]byte(words[1]), &snatComment)
				if err != nil {
					panic(err)
				}
				snat.FWSMGlobalId = snatComment.FWSMGlobalId
				source.IfName     = snatComment.IfName
				words = words[2:]

			case "-j":
				if words[1] != "SNAT" || words[2] != "--to-source" {
					panic("illegal rule: "+ruleString)
				}
				snat.NATTo = net.ParseIP(words[3])
				words = words[4:]

			default:
				panic(fmt.Errorf("%v: %v: %v", errNotImplemented, words, ruleString))
			}
		}
		snat.Sources = append(snat.Sources, source)

		result = append(result, &snat)
	}
	return
}
func (fw iptables) InquireDNATs() (result networkControl.DNATs) {
	ruleStrings, err := fw.iptables.List("nat", "DNATs")
	if err != nil {
		panic(err)
	}
	for _, ruleString := range ruleStrings {
		words := strings.Split(ruleString, " ")
		if words[0] == "-N" {
			break
		}
		dnat := networkControl.DNAT{}
		destination := networkControl.IPPort{}
		for len(words) > 0 {
			switch words[0] {
			case "-i":
				words = words[2:]

			case "-m":
				words = words[2:]

			case "-d":
				var err error
				destination.IP = net.ParseIP(words[1])
				if err != nil {
					panic(err)
				}
				words = words[2:]

			case "-p":
				proto := networkControl.ProtocolFromString(words[1])
				destination.Protocol = &proto

			case "--dport":
				port, err := strconv.Atoi(words[1])
				if err != nil {
					panic(err)
				}
				portU16 := uint16(port)
				destination.Port = &portU16
				dnat.NATTo.Port = &portU16
				words = words[2:]

			case "--comment":
				dnatComment := dnatCommentT{}
				err := json.Unmarshal([]byte(words[1]), &dnatComment)
				if err != nil {
					panic(err)
				}
				dnat.IfName = dnatComment.IfName
				words = words[2:]

			case "-j":
				if words[1] != "DNAT" || words[2] != "--to-destination" {
					panic("illegal rule: "+ruleString)
				}
				dnat.NATTo.IP = net.ParseIP(words[3])
				words = words[4:]

			default:
				panic(fmt.Sprintf("%v: %v: %v", errNotImplemented, words, ruleString))
			}
		}
		dnat.Destinations = append(dnat.Destinations, destination)

		result = append(result, &dnat)
	}
	return
}

func ruleToNetfilterRule(rule networkControl.ACLRule) (result []string) {
	protocolString := rule.Protocol.String()
	if protocolString != "ip" {
		result = append(result, "-p", protocolString)
	}

	result = append(result, "-s", rule.FromNet.String(), "-d", rule.ToNet.String())

	if len(rule.FromPortRanges) != 1 || len(rule.ToPortRanges) != 1 {
		panic(fmt.Errorf("%v: %v, %v: %v", errNotImplemented, rule.FromPortRanges, rule.ToPortRanges, rule))
	}

	if rule.FromPortRanges[0].Start != 0 || rule.FromPortRanges[0].End != 65535 || rule.ToPortRanges[0].Start != 0 || rule.ToPortRanges[0].End != 65535 {
		result = append(result, "-m", "multiport")
		result = append(result, "--sports", portRangesToNetfilterPorts(rule.FromPortRanges), "--dports", portRangesToNetfilterPorts(rule.ToPortRanges))
	}

	var action string
	switch rule.Action {
	case networkControl.ACL_ALLOW:
		action = "ACCEPT"
	case networkControl.ACL_DENY:
		action = "REJECT"
	default:
		panic(fmt.Errorf("Unknown action: %v", rule))
	}

	result = append(result, "-j", action)

	return result
}

func portRangesToNetfilterPorts(portRanges networkControl.PortRanges) string {
	convPortRanges := []string{}

	for _, portRange := range portRanges {
		convPortRanges = append(convPortRanges, fmt.Sprintf("%v:%v", portRange.Start, portRange.End))
	}

	return strings.Join(convPortRanges, ",")
}

func ParseNetfilterPortRanges(portRangesString string) (portRanges networkControl.PortRanges) {
	portRangeStrings := strings.Split(portRangesString, ",")

	for _, portRangeString := range portRangeStrings {
		portRangeWords := strings.Split(portRangeString, ":")
		if len(portRangeWords) == 1 {
			portRangeWords = append(portRangeWords, portRangeWords[0])
		}

		portRangeStart, err := strconv.Atoi(portRangeWords[0])
		if err != nil {
			panic(err)
		}
		portRangeEnd, err := strconv.Atoi(portRangeWords[1])
		if err != nil {
			panic(err)
		}

		portRange := networkControl.PortRange{
			Start: uint16(portRangeStart),
			End: uint16(portRangeEnd),
		}

		portRanges = append(portRanges, portRange)
	}

	return
}

func parseACLRule(ruleString string) (rule networkControl.ACLRule) {
	words := strings.Split(ruleString, " ")
	for len(words) > 0 {
		switch words[0] {
		case "-m":
			words = words[2:]
		case "-s":
			var err error
			rule.FromNet, err = networkControl.IPNetFromCIDRString(words[1])
			if err != nil {
				panic(err)
			}
			words = words[2:]
		case "-d":
			var err error
			rule.ToNet, err = networkControl.IPNetFromCIDRString(words[1])
			if err != nil {
				panic(err)
			}
			words = words[2:]
		case "-p":
			rule.Protocol = networkControl.ProtocolFromString(words[1])
			words = words[2:]
		case "--sports":
			rule.ToPortRanges = ParseNetfilterPortRanges(words[1])
			words = words[2:]
		case "--dports":
			rule.FromPortRanges = ParseNetfilterPortRanges(words[1])
			words = words[2:]
		case "-j":
			switch words[1] {
			case "ACCEPT":
				rule.Action = networkControl.ACL_ALLOW
			case "DROP", "REJECT":
				rule.Action = networkControl.ACL_DENY
			}
			words = words[2:]
		case "--reject-with":
			words = words[2:]
		default:
			panic(fmt.Errorf("%v: %v: %v", errNotImplemented, words, ruleString))
		}
	}

	return
}

func (fw *iptables) AddACL(acl networkControl.ACL) (err error) {

	setName := "ACL.IN." + acl.Name
	chainName := setName

	// adding an ipset

	var set *ipset.IPSet
	set, err = ipset.New(setName, "hash:net,iface", &ipset.Params{})
	if err != nil {
		return
	}
	for _, vlanName := range acl.VLANNames {
		err = set.Add("0.0.0.0/0,"+vlanName, 0)
		if err != nil {
			return
		}
	}

	// adding a chain to iptables

	err = fw.iptables.NewChain("filter", chainName)
	if err != nil {
		fw.LogError(err)
		return err
	}
	for _, rule := range acl.Rules {
		err = fw.iptables.AppendUnique("filter", chainName, ruleToNetfilterRule(rule)...)
		if err != nil {
			return
		}
	}

	// activating the chain

	return fw.iptables.AppendUnique("filter", "ACLs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
}

type dnatCommentT struct {
	IfName string `json:",omitempty"`
}

func (c dnatCommentT) Json() string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func (c dnatCommentT) String() string {
	return c.Json()
}

type snatCommentT struct {
	FWSMGlobalId int    `json:",omitempty"`
	IfName       string `json:",omitempty"`
}

func (c snatCommentT) Json() string {
	b, err := json.Marshal(c)
	if err != nil {
		panic(err)
	}
	return string(b)
}
func (c snatCommentT) String() string {
	return c.Json()
}

func (fw iptables) snatRuleStrings(snat networkControl.SNAT, source networkControl.SNATSource) []string {
	snatComment := snatCommentT{
		FWSMGlobalId: snat.FWSMGlobalId,
		IfName:       source.IfName,
	}
	return []string{"-s", source.IPNet.String(), "-j", "SNAT", "--to-source", snat.NATTo.String(), "-m", "comment", "--comment", snatComment.Json()}
}

func (fw *iptables) AddSNAT(snat networkControl.SNAT) error {
	for _, source := range snat.Sources {
		err := fw.iptables.AppendUnique("nat", "SNATs", fw.snatRuleStrings(snat, source)...)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}
	return nil
}

func ipportToNetfilterIPPort(ipport networkControl.IPPort, isDst bool) (result []string) {
	if isDst {
		result = append(result, "-d")
	} else {
		result = append(result, "-s")
	}
	result = append(result, ipport.IP.String())

	if ipport.Protocol != nil {
		if ipport.Protocol.String() == "ip" {
			ipport.Protocol = nil
		}
	}

	if ipport.Port == nil && ipport.Protocol == nil {
		return
	}
	if ipport.Port == nil || ipport.Protocol == nil {
		panic(fmt.Errorf("This case is not implemented: %v %v: %v", ipport.Port, ipport.Protocol, ipport))
	}
	result = append(result, "-p", ipport.Protocol.String())
	if isDst {
		result = append(result, "--dport")
	} else {
		result = append(result, "--sport")
	}
	result = append(result, strconv.Itoa(int(*ipport.Port)))

	return
}

func ipportToShortNetfilterIPPort(ipport networkControl.IPPort) string {
	if ipport.Protocol != nil {
		if ipport.Protocol.String() == "ip" {
			ipport.Protocol = nil
		}
	}

	if ipport.Port == nil && ipport.Protocol == nil {
		return ipport.IP.String()
	}
	if ipport.Port == nil || ipport.Protocol == nil {
		panic("This case is not implemented")
	}
	return fmt.Sprintf("%v:%v", ipport.IP, *ipport.Port)
}

func (fw iptables) dnatRuleStrings(dnat networkControl.DNAT, destination networkControl.IPPort) []string {
	dnatComment := dnatCommentT{
		IfName: dnat.IfName,
	}

	rule := []string{"-i", fw.IfNameToIPTIfName(dnat.IfName)}
	rule = append(rule, ipportToNetfilterIPPort(destination, true)...)
	rule = append(rule, "-j", "DNAT", "--to-destination", ipportToShortNetfilterIPPort(dnat.NATTo), "-m", "comment", "--comment", dnatComment.Json())

	return rule
}

func (fw *iptables) AddDNAT(dnat networkControl.DNAT) error {
	for _, destination := range dnat.Destinations {
		err := fw.iptables.AppendUnique("nat", "DNATs", fw.dnatRuleStrings(dnat, destination)...)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}
	return nil
}
func (fw *iptables) UpdateACL(acl networkControl.ACL) error {
	panic(fmt.Errorf("%v: %v", errNotImplemented.Error(), acl))
	return errNotImplemented
}
func (fw *iptables) UpdateSNAT(snat networkControl.SNAT) error {
	panic(errNotImplemented)
	return errNotImplemented
}
func (fw *iptables) UpdateDNAT(dnat networkControl.DNAT) error {
	panic(errNotImplemented)
	return errNotImplemented
}
func (fw *iptables) RemoveACL(acl networkControl.ACL) error {

	setName := "ACL.IN." + acl.Name
	chainName := setName

	// deactivating the chain

	err := fw.iptables.Delete("filter", "ACLs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
	if err != nil {
		fw.LogError(err)
		return err
	}

	// removing the chain

	err = fw.iptables.ClearChain("filter", chainName)
	if err != nil {
		fw.LogError(err)
		return err
	}
	err = fw.iptables.DeleteChain("filter", chainName)
	if err != nil {
		fw.LogError(err)
		return err
	}

	// removing the set

	return ipset.Destroy(setName)
}
func (fw *iptables) RemoveSNAT(snat networkControl.SNAT) error {
	for _, source := range snat.Sources {
		err := fw.iptables.Delete("nat", "SNATs", fw.snatRuleStrings(snat, source)...)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}
	return nil
}
func (fw *iptables) RemoveDNAT(dnat networkControl.DNAT) error {
	for _, destination := range dnat.Destinations {
		err := fw.iptables.Delete("nat", "DNATs", fw.dnatRuleStrings(dnat, destination)...)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}
	return nil
}
