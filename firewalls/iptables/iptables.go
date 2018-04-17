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

	ok, _ := fw.iptables.Exists("filter", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if !ok {
		err := fw.iptables.Insert("filter", "FORWARD", 1, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if err != nil {
			panic(err)
		}
	}
	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "ACLs")
	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "SECURITY_LEVELs")
	fw.iptables.AppendUnique("nat", "PREROUTING", "-j", "DNATs")
	/*fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "10.0.0.0/8", "-j", "ACCEPT")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "172.16.0.0/12", "-j", "ACCEPT")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "192.168.0.0/16", "-j", "ACCEPT")*/
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-j", "SNATs")

	return fw
}

func (fw iptables) InquireSecurityLevel(ifName string) int {
	setNames, err := ipset.Names()
	if err != nil {
		panic(err)
	}

	iptIfName := fw.IfNameToIPTIfName(ifName)

	// TODO: sort setNames numberically before the "for" below

	// Searching for IFACES.SECURITY_LEVEL.###
	for _, setName := range setNames {
		if !strings.HasPrefix(setName, "IFACES.SECURITY_LEVEL.") {
			continue
		}

		chainName := setName
		iptOk, err := fw.iptables.Exists("filter", "SECURITY_LEVELs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
		if err != nil && strings.Index(err.Error(), "No such file or directory") == -1 {
			panic(err)
		}
		if !iptOk {
			continue
		}

		setNameWords := strings.Split(setName, ".")
		securityLevel, err := strconv.Atoi(setNameWords[2])
		if err != nil {
			fmt.Fprintf(os.Stderr, "Invalid security level value \"%v\" (in ipset name: %v): %v", setNameWords[2], setName, err.Error())
			continue
		}

		ok, err := ipset.Test(setName, "0.0.0.0/0,"+iptIfName)
		if err != nil && strings.Index(err.Error(), "is NOT in set") == -1 {
			panic(err)
		}
		if ok {
			return securityLevel
		}
	}

	fw.Infof("Cannot find security level of iface %v", ifName)
	return -1
}

func (fw *iptables) createSecurityLevelRules() (err error) {
	setNames, err := ipset.Names()
	fw.Infof("iptables.createSecurityLevelRules(): setNames == %v", setNames)
	if err != nil {
		fw.LogError(err)
		return err
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
			fw.Warningf("Invalid security level value \"%v\" (in ipset name: %v): %v", setNameWords[2], setName, err.Error())
			err := ipset.Destroy(setName)
			if err != nil {
				fw.Errorf("Cannot delete the set \"%v\" of the invalid security level: %v", setName, err.Error())
			}
			continue
		}

		securityLevels = append(securityLevels, securityLevel)
	}

	fw.Infof("iptables.createSecurityLevelRules(): %v", securityLevels)

	for _, securityLevelA := range securityLevels {
		var setName string

		if securityLevelA >= 0 {
			setName = "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevelA)
		} else {
			setName = "IFACES.SECURITY_LEVEL.m" + strconv.Itoa(-securityLevelA)
		}
		chainName := setName

		{
			err := fw.iptables.NewChain("filter", chainName)
			if err != nil && strings.Index(err.Error(), "Chain already exists") == -1 {
				fw.LogError(err)
				return err
			}
		}

		var minSecurityLevelB int
		minSecurityLevelB = 65535
		for _, securityLevelB := range securityLevels {
			if securityLevelB >= securityLevelA {
				continue
			}
			if securityLevelB < minSecurityLevelB {
				minSecurityLevelB = securityLevelB
			}
		}

		var setNameB string
		var chainNameB string
		if minSecurityLevelB != 65535 {
			if minSecurityLevelB >= 0 {
				setNameB = "IFACES.SECURITY_LEVEL." + strconv.Itoa(minSecurityLevelB)
			} else {
				setNameB = "IFACES.SECURITY_LEVEL.m" + strconv.Itoa(-minSecurityLevelB)
			}
			chainNameB = setNameB

			err := fw.iptables.NewChain("filter", chainNameB)
			if err != nil && strings.Index(err.Error(), "Chain already exists") == -1 {
				fw.LogError(err)
				return err
			}
		}

		fw.Infof("iptables.createSecurityLevelRules(): R: %v %v | %v %v | %v %v", securityLevelA, minSecurityLevelB, chainName, setName, chainNameB, setNameB)

		fw.iptables.ClearChain("filter", chainName)
		if chainNameB != "" {
			err := fw.iptables.AppendUnique("filter", chainName, "-j", chainNameB)
			if err != nil {
				fw.LogError(err)
				return err
			}
		}

		{
			var err error
			if fw.isSameSecurityTraffic {
				err = fw.iptables.AppendUnique("filter", chainName, "-m", "set", "--match-set", setName, "dst,dst", "-j", "ACCEPT")
			} else {
				if setNameB != "" {
					err = fw.iptables.AppendUnique("filter", chainName, "-m", "set", "--match-set", setNameB, "dst,dst", "-j", "ACCEPT")
				}
			}
			if err != nil {
				fw.LogError(err)
				return err
			}
		}

		{
			var err error
			//if fw.isSameSecurityTraffic {
			err = fw.iptables.AppendUnique("filter", "SECURITY_LEVELs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
			/*} else {
				if chainNameB != "" {
					err = fw.iptables.AppendUnique("filter", "SECURITY_LEVELs", "-m", "set", "--match-set", setName, "src,src", "-j", chainNameB)
				}
			}*/
			if err != nil {
				fw.LogError(err)
				return err
			}
		}

		deleteOld, err := fw.iptables.Exists("filter", "SECURITY_LEVELs", "-j", "REJECT")
		if err != nil {
			fw.LogError(err)
			return err
		}
		err = fw.iptables.Append("filter", "SECURITY_LEVELs", "-j", "REJECT")
		if err != nil {
			fw.LogError(err)
			return err
		}
		if deleteOld {
			err = fw.iptables.Delete("filter", "SECURITY_LEVELs", "-j", "REJECT")
			if err != nil {
				fw.LogError(err)
				return err
			}
		}
	}

	return nil
}

func (fw *iptables) addSecurityLevel(securityLevel int) error {
	var setName string
	if securityLevel >= 0 {
		setName = "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevel)
	} else {
		setName = "IFACES.SECURITY_LEVEL.m" + strconv.Itoa(-securityLevel)
	}
	_, err := ipset.New(setName, "hash:net,iface", &ipset.Params{HashSize: 1048576})
	if err != nil && strings.Index(err.Error(), "set with the same name already exists") == -1 {
		fw.Errorf("iptables.addSecurityLevel(%v): %v", securityLevel, err)
		return err
	}

	return fw.createSecurityLevelRules()
}

func (fw *iptables) SetSecurityLevel(ifName string, securityLevel int) (err error) {
	setName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevel)
	fw.Infof("iptables.SetSecurityLevel(%v, %v): %v", ifName, securityLevel, setName)

	if securityLevel < 0 {
		fw.Warningf("securityLevel < 0: %v", securityLevel)
	}

	// Remembering the old security level set name

	oldSecurityLevel := fw.InquireSecurityLevel(ifName)
	oldSetName := "IFACES.SECURITY_LEVEL." + strconv.Itoa(oldSecurityLevel)

	// If nothing to do then return
	if setName == oldSetName {
		return nil
	}

	// Create the security level if not exists

	err = fw.addSecurityLevel(securityLevel)
	if err != nil {
		fw.LogError(err)
		return err
	}

	// Adding to the new security level

	err = ipset.Add(setName, "0.0.0.0/0,"+fw.IfNameToIPTIfName(ifName), 0)
	if err != nil {
		fw.LogError(err, securityLevel, setName, ifName)
		return err
	}

	// Removing from the old security level

	ipset.Del(oldSetName, "0.0.0.0/0,"+fw.IfNameToIPTIfName(ifName))

	return nil
}

func (fw iptables) IfNameToIPTIfName(ifName string) string {
	return fw.GetHost().IfNameToHostIfName(ifName)
}
func (fw iptables) IPTIfNameToIfName(ifName string) string {
	return fw.GetHost().HostIfNameToIfName(ifName)
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
		ifName := fw.IPTIfNameToIfName(words[1])
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
	snatMap := map[string]*networkControl.SNAT{}
	for _, ruleString := range ruleStrings {
		words := strings.Split(ruleString, " ")
		if words[0] == "-N" {
			continue
		}
		if words[0] != "-A" {
			panic(fmt.Errorf("%v: %v: %v", errNotImplemented, words, ruleString))
		}
		words = words[1:]
		if words[0] != "SNATs" {
			continue
		}
		words = words[1:]
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
				commentStr, err := strconv.Unquote(words[1])
				if err != nil {
					panic(fmt.Errorf("%v: %v", err, words[1]))
				}
				err = json.Unmarshal([]byte(commentStr), &snatComment)
				if err != nil {
					panic(fmt.Errorf("%v: %v", err, commentStr))
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
		snatKey := snat.NATTo.String()
		if snatMap[snatKey] == nil {
			snat.Sources = append(snat.Sources, source)
			snatMap[snatKey] = &snat
		} else {
			snatMap[snatKey].Sources = append(snatMap[snatKey].Sources, source)
		}
	}

	for _, snat := range snatMap {
		snat.Sources = snat.Sources.Sort()
		result = append(result, snat)
	}

	fw.Debugf("InquireSNATs(): %v", len(result))
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
			continue
		}
		if words[0] != "-A" {
			panic(fmt.Errorf("%v: %v: %v", errNotImplemented, words, ruleString))
		}
		words = words[1:]
		if words[0] != "DNATs" {
			continue
		}
		words = words[1:]
		dnat := networkControl.DNAT{}
		destination := networkControl.IPPort{}
		for len(words) > 0 {
			switch words[0] {
			/*case "-i":
				words = words[2:]*/

			case "-m":
				words = words[2:]

			case "-d":
				var err error
				subWords := strings.Split(words[1], "/")
				if len(subWords) > 1 && subWords[1] != "32" {
					panic(fmt.Sprintf("%v: %v: %v", errNotImplemented, subWords, words, ruleString))
				}
				destination.IP = net.ParseIP(subWords[0])
				if err != nil {
					panic(err)
				}
				words = words[2:]

			case "-p":
				proto := networkControl.ProtocolFromString(words[1])
				destination.Protocol = &proto
				dnat.NATTo.Protocol = &proto
				words = words[2:]

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
				commentStr, err := strconv.Unquote(words[1])
				if err != nil {
					panic(fmt.Errorf("%v: %v", err, words[1]))
				}
				err = json.Unmarshal([]byte(commentStr), &dnatComment)
				if err != nil {
					panic(fmt.Errorf("%v: %v", err, commentStr))
				}
				dnat.IfName = dnatComment.IfName
				words = words[2:]

			case "-j":
				if words[1] != "DNAT" || words[2] != "--to-destination" {
					panic("illegal rule: "+ruleString)
				}
				dnat.NATTo.Parse(words[3])
				words = words[4:]

			default:
				panic(fmt.Sprintf("%v: %v: %v", errNotImplemented, words, ruleString))
			}
		}
		dnat.Destinations = append(dnat.Destinations, destination)

		result = append(result, &dnat)
	}

	fw.Debugf("InquireDNATs(): %v", len(result))
	return
}

func ruleToNetfilterRule(rule networkControl.ACLRule) (result []string) {
	protocolString := rule.Protocol.String()
	if protocolString != "ip" {
		result = append(result, "-p", protocolString)
	}

	if rule.FromNet.String() != "0.0.0.0/0" {
		result = append(result, "-s", rule.FromNet.String())
	}
	if rule.ToNet.String() != "0.0.0.0/0" {
		result = append(result, "-d", rule.ToNet.String())
	}

	if len(rule.FromPortRanges) != 1 || len(rule.ToPortRanges) != 1 {
		panic(fmt.Errorf("%v: %v, %v: %v", errNotImplemented, rule.FromPortRanges, rule.ToPortRanges, rule))
	}


	if rule.FromPortRanges[0].Start != 0 || rule.FromPortRanges[0].End != 65535 || rule.ToPortRanges[0].Start != 0 || rule.ToPortRanges[0].End != 65535 {
		if rule.FromPortRanges[0].Start != rule.FromPortRanges[0].End || rule.ToPortRanges[0].Start != rule.ToPortRanges[0].End {
			result = append(result, "-m", "multiport")
		}
	}
	if rule.FromPortRanges[0].Start != 0 || rule.FromPortRanges[0].End != 65535 {
		if rule.FromPortRanges[0].Start != rule.FromPortRanges[0].End {
			result = append(result, "--sports")
		} else {
			result = append(result, "--sport")
		}
		result = append(result, portRangesToNetfilterPorts(rule.FromPortRanges))
	}
	if rule.ToPortRanges[0].Start != 0 || rule.ToPortRanges[0].End != 65535 {
		if rule.ToPortRanges[0].Start != rule.ToPortRanges[0].End {
			result = append(result, "--dports")
		} else {
			result = append(result, "--dport")
		}
		result = append(result, portRangesToNetfilterPorts(rule.ToPortRanges))
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
		if portRange.Start == portRange.End {
			convPortRanges = append(convPortRanges, fmt.Sprintf("%v", portRange.Start))
		} else {
			convPortRanges = append(convPortRanges, fmt.Sprintf("%v:%v", portRange.Start, portRange.End))
		}
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
	set, err = ipset.New(setName, "hash:net,iface", &ipset.Params{HashSize: 1048576})
	if err != nil {
		return
	}
	for _, vlanName := range acl.VLANNames {
		err = set.Add("0.0.0.0/0,"+fw.IfNameToIPTIfName(vlanName), 0)
		if err != nil {
			fw.LogError(err)
			return
		}
	}

	// adding a chain to iptables

	err = fw.iptables.NewChain("filter", chainName)
	if err != nil {
		if err.Error() == "Chain already exists." {
			fw.LogWarning(err)
		} else {
			fw.LogError(err)
			return err
		}
	}
	for _, rule := range acl.Rules {
		err = fw.iptables.AppendUnique("filter", chainName, ruleToNetfilterRule(rule)...)
		if err != nil {
			fw.LogError(err)
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
		panic(fmt.Errorf("This case is not implemented: %v", ipport))
	}
	return fmt.Sprintf("%v:%v", ipport.IP, *ipport.Port)
}

func (fw iptables) dnatRuleStrings(dnat networkControl.DNAT, destination networkControl.IPPort) []string {
	dnatComment := dnatCommentT{
		IfName: dnat.IfName,
	}

	rule := []string{}
	//rule = append(rule, "-i", fw.IfNameToIPTIfName(dnat.IfName))
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
	fw.RemoveACL(acl)
	return fw.AddACL(acl)
}
func (fw *iptables) UpdateSNAT(snat networkControl.SNAT) error {
	fw.RemoveSNAT(snat)
	return fw.AddSNAT(snat)
}
func (fw *iptables) UpdateDNAT(dnat networkControl.DNAT) error {
	fw.RemoveDNAT(dnat)
	return fw.AddDNAT(dnat)
}
func (fw *iptables) RemoveACL(acl networkControl.ACL) error {

	setName := "ACL.IN." + acl.Name
	chainName := setName

	// deactivating the chain

	err := fw.iptables.Delete("filter", "ACLs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
	if err != nil {
		if err.Error() == "No chain/target/match by that name." {
			fw.LogError(err)
			return err
		} else {
			fw.LogWarning(err)
		}
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
