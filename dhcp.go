package networkControl

import (
	"net"
)

type DHCPOptionValueType int

const (
	DHCPOPT_UNKNOWN = DHCPOptionValueType(0)
	DHCPOPT_ASCII   = DHCPOptionValueType(1)
)

type DHCPCommon struct {
	NSs     NSs
	Options DHCPOptions
	Domain  Domain
}

type DHCP struct {
	DHCPCommon

	RangeStart net.IP
	RangeEnd   net.IP

	// for FWSM config only:
	IfName string
}

type DHCPOption struct {
	Id        int
	ValueType DHCPOptionValueType
	Value     []byte
}

type DHCPOptions []DHCPOption
type DHCPs []DHCP
