package networkControl

import (
	"net"
)

type SNATSource struct {
	IPNet

	// for FWSM config only?
	IfName string
}

type SNATSources []SNATSource

type SNAT struct {
	Sources SNATSources
	NATTo   net.IP

	// for FWSM config only:
	FWSMGlobalId int
}

type DNAT struct {
	Destinations IPPorts
	NATTo        IPPort

	// for FWSM config only?
	IfName string
}

type SNATs []*SNAT
type DNATs []*DNAT

func (a SNATs) Len() int           { return len(a) }
func (a SNATs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SNATs) Less(i, j int) bool { return a[i].FWSMGlobalId < a[j].FWSMGlobalId }

func (a DNATs) Len() int           { return len(a) }
func (a DNATs) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a DNATs) Less(i, j int) bool { return a[i].GetPos() < a[j].GetPos() }

/*func (snat SNAT) GetPos() string {
	return snat.NATTo.String()
}*/

func (dnat DNAT) GetPos() string {
	return dnat.NATTo.String()
}


func (snat SNAT) KeyStringValue() string {
	return snat.NATTo.String()
}
func (dnat DNAT) KeyStringValue() string {
	return dnat.NATTo.String()
}
