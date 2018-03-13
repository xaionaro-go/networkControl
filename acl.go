package networkControl

// ACL is a model used mainly for Cisco equipment only

import ()

type ACLAction int

const (
	ACL_ALLOW = ACLAction(1)
	ACL_DENY  = ACLAction(2)
)

type ACLFlags uint16

const (
	ACLFL_ESTABLISHED = ACLFlags(0x01)
)

type ACLRule struct {
	Action         ACLAction
	Protocol       Protocol
	FromNet        IPNet
	FromPortRanges PortRanges
	ToNet          IPNet
	ToPortRanges   PortRanges
	Flags          ACLFlags
}

type ACLRules []ACLRule

type ACL struct {
	Name      string
	Rules     ACLRules
	VLANNames []string
}

type ACLs []*ACL

func (a ACLs) Len() int           { return len(a) }
func (a ACLs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ACLs) Less(i, j int) bool { return a[i].Name < a[j].Name }

func (acl ACL) KeyStringValue() string {
	return acl.Name
}

