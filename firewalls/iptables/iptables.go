package iptables

import (
	"encoding/json"
	"errors"
	"fmt"
	ipt "github.com/coreos/go-iptables/iptables"
	"github.com/xaionaro-go/networkControl"
	"net"
	"strconv"
	"strings"
)

var (
	errNotImplemented = errors.New("not implemented (yet?)")
	denyCommand       = `DROP`
	denyToOtherGWs    = true
)

type iptables struct {
	networkControl.FirewallBase
	iptables              *ipt.IPTables
	isSameSecurityTraffic bool

	markToSecurityLevel   map[int]*int
	securityLevelToMark   map[int]int
	markMax_securityLevel int

	markToACL   map[int]string
	aclToMark   map[string]int
	markMax_ACL int
}

func NewFirewall(host networkControl.HostI) networkControl.FirewallI {
	newIPT, err := ipt.New()
	if err != nil {
		panic(err)
	}

	fw := &iptables{
		iptables:              newIPT,
		isSameSecurityTraffic: true,
		markToSecurityLevel:   map[int]*int{},
		securityLevelToMark:   map[int]int{},
		markToACL:             map[int]string{},
		aclToMark:             map[string]int{},
	}

	fw.SetHost(host)

	fw.iptables.NewChain("mangle", "ACLs")
	fw.iptables.NewChain("mangle", "IN_SECURITY_LEVELs")
	fw.iptables.NewChain("mangle", "OUT_SECURITY_LEVELs")
	fw.iptables.NewChain("filter", "ACLs")
	fw.iptables.NewChain("filter", "ACCEPT_DNATs")
	fw.iptables.NewChain("filter", "SECURITY_LEVELs")
	fw.iptables.NewChain("nat", "SNATs")
	fw.iptables.NewChain("nat", "DNATs")

	fw.iptables.AppendUnique("mangle", "FORWARD", "-j", "ACLs")
	fw.iptables.AppendUnique("mangle", "FORWARD", "-j", "IN_SECURITY_LEVELs")
	fw.iptables.AppendUnique("mangle", "FORWARD", "-j", "OUT_SECURITY_LEVELs")

	ok, _ := fw.iptables.Exists("filter", "FORWARD", "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
	if !ok {
		err := fw.iptables.Insert("filter", "FORWARD", 1, "-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-j", "ACCEPT")
		if err != nil {
			panic(err)
		}
	}
	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "ACLs")
	fw.iptables.AppendUnique("filter", "ACLs", "-j", "ACCEPT_DNATs")
	//fw.iptables.AppendUnique("filter", "FORWARD", "-j", "MARK", "--set-mark", "0x1000000/0x1000000", "-m", "comment", "--comment", "mark that this packet is not mine (a forwarded packet)")
	//fw.iptables.AppendUnique("filter", "OUTPUT", "-m", "mark", "!", "--mark", "0x1000000/0x1000000", "-j", "ACCEPT", "-m", "comment", "--comment", "it's my traffic, it should not be filtered")
	fw.iptables.AppendUnique("filter", "FORWARD", "-j", "SECURITY_LEVELs")
	if denyToOtherGWs {
		fw.iptables.AppendUnique("filter", "INPUT", "-m", "addrtype", "!", "--dst-type", "LOCAL", " --limit-iface-in", "-j", denyCommand)
	}
	fw.iptables.AppendUnique("nat", "PREROUTING", "-j", "DNATs")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "10.0.0.0/8", "-j", "ACCEPT")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "172.16.0.0/12", "-j", "ACCEPT")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-d", "192.168.0.0/16", "-j", "ACCEPT")
	fw.iptables.AppendUnique("nat", "POSTROUTING", "-j", "SNATs")

	// TODO: remove this hack (update "--comment"-s correctly)
	/*fw.iptables.ClearChain("filter", "ACLs")
	fw.iptables.ClearChain("filter", "SECURITY_LEVELs")
	fw.iptables.ClearChain("mangle", "ACLs")
	fw.iptables.ClearChain("mangle", "IN_SECURITY_LEVELs")
	fw.iptables.ClearChain("mangle", "OUT_SECURITY_LEVELs")*/

	return fw
}

func (fw *iptables) SetEnablePermitInterInterface(enable bool) error {
	//fw.isSameSecurityTraffic = enable
	return nil
}
func (fw *iptables) SetEnablePermitIntraInterface(enable bool) error {
	return nil
}

func (fw iptables) GetSecurityLevels() (securityLevels []int) {
	/*
		chainNames := fw.iptables.ListChains("filter")
		for _, chainName := range chainNames {
			if strings.Index(chainName, "IFACES.SECURITY_LEVEL.") != 0 {
				continue
			}
			words := strings.Split(chainName, ".")
			securityLevelString := words[2]
			securityLevel, err := strconv.Atoi(securityLevelString)
			if err != nil {
				fw.LogError(err, securityLevelString)
				continue
			}
			securityLevels = append(securityLevels, securityLevel)
		}

		return
	*/
	for securityLevel, _ := range fw.securityLevelToMark {
		securityLevels = append(securityLevels, securityLevel)
	}

	return
}

func (fw iptables) InquireSecurityLevel(ifName string) int {
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/
	ruleStrings, err := fw.iptables.List("mangle", "IN_SECURITY_LEVELs")
	for _, ruleString := range ruleStrings {
		var ruleIfName string
		isIfaceRule := false
		ruleWords := strings.Split(ruleString, " ")
		var mark int
		for idx, ruleWord := range ruleWords {
			switch ruleWord {
			case "-i":
				ruleIfName = ruleWords[idx+1]
			case "--set-xmark":
				markString := strings.Split(ruleWords[idx+1], "/")[0]
				mark64, err := strconv.ParseInt(markString, 0, 32)
				if err == nil {
					mark = int(mark64)
					isIfaceRule = true
				} else {
					fw.LogError(err, ruleString)
				}
			}
		}
		if !isIfaceRule {
			continue
		}
		if ruleIfName == "" {
			fw.Errorf(`ifName == ""`)
			continue
		}
		if fw.GetHost().IfNameToHostIfName(ifName) != ruleIfName {
			continue
		}
		securityLevel := fw.MarkToSecurityLevel(mark)
		if err != nil {
			fw.LogError(err, mark)
			continue
		}
		return securityLevel
	}
	fw.Infof("Cannot find security level of iface %v", ifName)
	return -1
}

func (fw *iptables) createSecurityLevelRules() (err error) {
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/

	securityLevels := fw.GetSecurityLevels()

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

		/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
			err = fw.iptables.AppendUnique("filter", "SECURITY_LEVELs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
			if err != nil {
				fw.LogError(err)
				return err
			}
		}
		*/

		{
			var err error
			if fw.isSameSecurityTraffic {
				err = fw.iptables.AppendUnique("filter", chainName, "-m", "mark", "--mark", (strconv.Itoa(fw.SecurityLevelToMark(securityLevelA)<<8))+"/0xff00", "-j", "ACCEPT")
			} else {
				if setNameB != "" {
					err = fw.iptables.AppendUnique("filter", chainName, "-m", "mark", "--mark", (strconv.Itoa(fw.SecurityLevelToMark(minSecurityLevelB)<<8))+"/0xff00", "-j", "ACCEPT")
				}
			}
			if err != nil {
				fw.LogError(err)
				return err
			}
		}
		{
			var err error
			err = fw.iptables.AppendUnique("filter", "SECURITY_LEVELs", "-m", "mark", "--mark", strconv.Itoa(fw.SecurityLevelToMark(securityLevelA))+"/0xff", "-j", chainName)
			if err != nil {
				fw.LogError(err)
				return err
			}
		}

		deleteOld, err := fw.iptables.Exists("filter", "SECURITY_LEVELs", "-j", denyCommand)
		if err != nil {
			fw.LogError(err)
			return err
		}
		err = fw.iptables.Append("filter", "SECURITY_LEVELs", "-j", denyCommand)
		if err != nil {
			fw.LogError(err)
			return err
		}
		if deleteOld {
			err = fw.iptables.Delete("filter", "SECURITY_LEVELs", "-j", denyCommand)
			if err != nil {
				fw.LogError(err)
				return err
			}
		}
	}

	return nil
}

func (fw *iptables) addSecurityLevel(securityLevel int) error {
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
	var setName string
	if securityLevel >= 0 {
		setName = "IFACES.SECURITY_LEVEL." + strconv.Itoa(securityLevel)
	} else {
		setName = "IFACES.SECURITY_LEVEL.m" + strconv.Itoa(-securityLevel)
	}
	_, err := ipset.New(setName, "hash:net,iface", &ipset.Params{HashSize: 4096, MaxElem: 4096})
	if err != nil && strings.Index(err.Error(), "set with the same name already exists") == -1 {
		fw.Errorf("iptables.addSecurityLevel(%v): %v", securityLevel, err)
		return err
	}

	return fw.createSecurityLevelRules()
	*/

	if fw.securityLevelToMark[securityLevel] == 0 {
		fw.markMax_securityLevel++
		fw.securityLevelToMark[securityLevel] = fw.markMax_securityLevel
		fw.markToSecurityLevel[fw.markMax_securityLevel] = &securityLevel
	}

	return fw.createSecurityLevelRules()
}

func (fw *iptables) MarkToSecurityLevel(mark int) int {
	securityLevelPtr := fw.markToSecurityLevel[mark]

	if securityLevelPtr != nil { // Found? Ok, returning
		return *securityLevelPtr
	}

	// Not found? Ok, scanning :(

	fw.Debugf("securityLevel == nil: %v", mark)
	ruleStrings, err := fw.iptables.List("filter", "SECURITY_LEVELs")
	if err != nil {
		fw.LogError(err)
	}
	for _, ruleString := range ruleStrings {
		var chainName string
		ruleMark := -1
		ruleWords := strings.Split(ruleString, " ")
		for idx, ruleWord := range ruleWords {
			switch ruleWord {
			case "-j":
				chainName = ruleWords[idx+1]
			case "--mark":
				markString := strings.Split(ruleWords[idx+1], "/")[0]
				mark64, err := strconv.ParseInt(markString, 0, 32)
				if err == nil {
					ruleMark = int(mark64)
				} else {
					fw.LogError(err, ruleString)
				}
			}
		}
		if ruleMark != mark {
			continue
		}
		// -A SECURITY_LEVELs -m mark --mark 0x1/0xff -j IFACES.SECURITY_LEVEL.50
		// -A SECURITY_LEVELs -m mark --mark 0x2/0xff -j IFACES.SECURITY_LEVEL.0
		chainNameWords := strings.Split(chainName, ".")
		securityLevel, err := strconv.Atoi(chainNameWords[2])
		if err != nil {
			fw.LogError(err, chainNameWords)
		}
		fw.markToSecurityLevel[mark] = &securityLevel
		return securityLevel
	}

	// Still not found?

	fw.Errorf("securityLevel == nil: %v", mark)
	return -1
}

func (fw iptables) SecurityLevelToMark(securityLevel int) int {
	mark := fw.securityLevelToMark[securityLevel]
	if mark == 0 {
		fw.Panicf("mark == 0", securityLevel)
	}
	return mark
}

func (fw *iptables) SetSecurityLevel(ifName string, securityLevel int) (err error) {
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/

	// Remembering the old security level

	oldSecurityLevel := fw.InquireSecurityLevel(ifName)
	if oldSecurityLevel == securityLevel {
		return nil
	}

	// Create the security level if not exists

	err = fw.addSecurityLevel(securityLevel)
	if err != nil {
		fw.LogError(err)
		return err
	}

	// Adding new security level rule

	err = fw.iptables.AppendUnique("mangle", "IN_SECURITY_LEVELs", "-i", fw.GetHost().IfNameToHostIfName(ifName), "-j", "MARK", "--set-mark", strconv.Itoa(fw.SecurityLevelToMark(securityLevel))+"/0xff", "-m", "comment", "--comment", "{security_level:"+strconv.Itoa(securityLevel)+"}")
	if err != nil {
		fw.LogError(err)
		return err
	}

	err = fw.iptables.AppendUnique("mangle", "OUT_SECURITY_LEVELs", "-o", fw.GetHost().IfNameToHostIfName(ifName), "-j", "MARK", "--set-mark", (strconv.Itoa(fw.SecurityLevelToMark(securityLevel)<<8))+"/0xff00", "-m", "comment", "--comment", "{security_level:"+strconv.Itoa(securityLevel)+"}")
	if err != nil {
		fw.LogError(err)
		return err
	}

	// Removing old security level rule

	if oldSecurityLevel != -1 {
		err = fw.iptables.Delete("mangle", "IN_SECURITY_LEVELs", "-i", fw.GetHost().IfNameToHostIfName(ifName), "-j", "MARK", "--set-mark", strconv.Itoa(fw.SecurityLevelToMark(oldSecurityLevel))+"/0xff", "-m", "comment", "--comment", "{security_level:"+strconv.Itoa(oldSecurityLevel)+"}")
		if err != nil {
			fw.LogError(err)
		}
		err = fw.iptables.Delete("mangle", "OUT_SECURITY_LEVELs", "-o", fw.GetHost().IfNameToHostIfName(ifName), "-j", "MARK", "--set-mark", (strconv.Itoa(fw.SecurityLevelToMark(oldSecurityLevel)<<8))+"/0xff00", "-m", "comment", "--comment", "{security_level:"+strconv.Itoa(oldSecurityLevel)+"}")
		if err != nil {
			fw.LogError(err)
		}
	}

	// finish

	return err
}

func (fw iptables) IfNameToIPTIfName(ifName string) string {
	return fw.GetHost().IfNameToHostIfName(ifName)
}
func (fw iptables) IPTIfNameToIfName(ifName string) string {
	return fw.GetHost().HostIfNameToIfName(ifName)
}

func (fw iptables) getACLsNames() (result []string) {
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/

	for acl, _ := range fw.aclToMark {
		result = append(result, acl)
	}

	return
}

func (fw *iptables) MarkToACL(mark int) string {
	aclName := fw.markToACL[mark]

	if aclName != "" { // Found? Ok, returning
		return aclName
	}

	// Not found? Ok, scanning :(

	fw.Debugf(`aclName == "": %v`, mark)
	ruleStrings, err := fw.iptables.List("filter", "ACLs")
	if err != nil {
		fw.LogError(err)
	}
	for _, ruleString := range ruleStrings {
		var chainName string
		ruleMark := -1
		ruleWords := strings.Split(ruleString, " ")
		for idx, ruleWord := range ruleWords {
			switch ruleWord {
			case "-j":
				chainName = ruleWords[idx+1]
			case "--mark":
				markString := strings.Split(ruleWords[idx+1], "/")[0]
				mark64, err := strconv.ParseInt(markString, 0, 32)
				if err == nil {
					ruleMark = int(mark64)
				} else {
					fw.LogError(err, ruleString)
				}
			}
		}
		if ruleMark != mark {
			continue
		}
		chainNameWords := strings.Split(chainName, ".")
		aclName := chainNameWords[2]
		if err != nil {
			fw.LogError(err, chainNameWords)
		}
		fw.markToACL[mark] = aclName
		return aclName
	}

	// Still not found?

	fw.Errorf(`aclName == "": %v`, mark)
	return ""
}

func (fw *iptables) ACLToMark(aclName string) int {
	mark := fw.aclToMark[aclName]
	if mark == 0 {
		fw.Panicf("mark == 0", aclName)
		return -1
	}
	return mark
}

func (fw iptables) inquireACL(aclName string) (result networkControl.ACL) {
	result.Name = aclName

	// Getting VLANs of the ACL
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/

	ruleStrings, err := fw.iptables.List("mangle", "ACLs")
	if err != nil {
		fw.LogPanic(err)
	}

	mark := fw.ACLToMark(aclName)
	for _, ruleString := range ruleStrings {
		var ifName string
		ruleMark := -1
		ruleWords := strings.Split(ruleString, " ")
		for idx, ruleWord := range ruleWords {
			switch ruleWord { // -A ACLs -i library_inside -j MARK --set-xmark 0x10000/0xff0000
			case "-i":
				ifName = ruleWords[idx+1]
			case "--set-xmark":
				markString := strings.Split(ruleWords[idx+1], "/")[0]
				mark64, err := strconv.ParseInt(markString, 0, 32)
				if err == nil {
					ruleMark = int(mark64)
				} else {
					fw.LogError(err, ruleString)
				}
			}
		}
		if ruleMark != mark {
			continue
		}
		result.VLANNames = append(result.VLANNames, ifName)
	}

	// Getting rules of the ACL

	chainName := "ACL.IN." + aclName

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
		fw.LogPanic(err)
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
				source.IfName = snatComment.IfName
				words = words[2:]

			case "-j":
				if words[1] != "SNAT" || words[2] != "--to-source" {
					panic("illegal rule: " + ruleString)
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
					panic(fmt.Sprintf("%v: %v: %v: %v", errNotImplemented, subWords, words, ruleString))
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
					panic("illegal rule: " + ruleString)
				}
				dnat.NATTo.Parse(words[3])
				words = words[4:]

			default:
				panic(fmt.Sprintf("%v: %v: %v", errNotImplemented, words, ruleString))
			}
		}
		dnat.Destinations = append(dnat.Destinations, destination)

		if ok, _ := fw.iptables.Exists("filter", "ACCEPT_DNATs", append(fw.ipportDestinationStrings(dnat.NATTo), "-j", "ACCEPT")...); !ok {
			continue
		}
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
		action = denyCommand
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
			End:   uint16(portRangeEnd),
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

	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
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
	*/

	if fw.aclToMark[acl.Name] == 0 {
		fw.markMax_ACL++
		mark := fw.markMax_ACL << 16
		fw.markToACL[mark] = acl.Name
		fw.aclToMark[acl.Name] = mark
	}

	for _, vlanName := range acl.VLANNames {
		err = fw.iptables.AppendUnique("mangle", "ACLs", "-i", fw.GetHost().IfNameToHostIfName(vlanName), "-j", "MARK", "--set-mark", strconv.Itoa(fw.ACLToMark(acl.Name))+"/0xff0000", "-m", "comment", "--comment", "{acl:"+acl.Name+"}")
		if err != nil {
			fw.LogError(err)
		}
	}

	// adding a chain to iptables

	err = fw.iptables.NewChain("filter", chainName)
	if err != nil {
		if strings.Index(err.Error(), "Chain already exists.") != -1 {
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

	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
	// activating the chain

	return fw.iptables.AppendUnique("filter", "ACLs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
	*/

	return fw.iptables.AppendUnique("filter", "ACLs", "-m", "mark", "--mark", strconv.Itoa(fw.ACLToMark(acl.Name))+"/0xff0000", "-j", chainName)
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

func (fw iptables) ipportDestinationStrings(ipport networkControl.IPPort) (r []string) {
	if ipport.Protocol != nil {
		if ipport.Protocol.String() != `ip` {
			r = append(r, `-p`, ipport.Protocol.String())
		}
	}
	r = append(r, `-d`, ipport.IP.String())
	if ipport.Port != nil {
		r = append(r, `--dport`, strconv.Itoa(int(*ipport.Port)))
	}

	return
}

func (fw *iptables) AddDNAT(dnat networkControl.DNAT) error {
	for _, destination := range dnat.Destinations {
		if err := fw.iptables.AppendUnique("nat", "DNATs", fw.dnatRuleStrings(dnat, destination)...); err != nil {
			fw.LogError(err)
			return err
		}

		if err := fw.iptables.AppendUnique("filter", "ACCEPT_DNATs", append(fw.ipportDestinationStrings(dnat.NATTo), "-j", "ACCEPT")...); err != nil {
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
	/* See https://bugzilla.kernel.org/show_bug.cgi?id=199107
	err := fw.iptables.Delete("filter", "ACLs", "-m", "set", "--match-set", setName, "src,src", "-j", chainName)
	if err != nil {
		if err.Error() == "No chain/target/match by that name." {
			fw.LogError(err)
			return err
		} else {
			fw.LogWarning(err)
		}
	}
	*/

	// removing the chain

	{
		err := fw.iptables.ClearChain("filter", chainName)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}

	{
		err := fw.iptables.DeleteChain("filter", chainName)
		if err != nil {
			fw.LogError(err)
			return err
		}
	}

	return nil

	// removing the set

	/* https://bugzilla.kernel.org/show_bug.cgi?id=199107
	return ipset.Destroy(setName)
	*/
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
		if err := fw.iptables.Delete("nat", "DNATs", fw.dnatRuleStrings(dnat, destination)...); err != nil {
			fw.LogError(err)
			return err
		}
		if err := fw.iptables.Delete("filter", "ACCEPT_DNATs", append(fw.ipportDestinationStrings(dnat.NATTo), "-j", "ACCEPT")...); err != nil {
			fw.LogError(err)
			return nil
		}
	}
	return nil
}
