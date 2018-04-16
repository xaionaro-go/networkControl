package networkControl

import (
	"fmt"
	"github.com/xaionaro-go/handySlices"
	"net"
	"sort"
	"strings"
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

func (source SNATSource) String() string { return fmt.Sprintf("%v/%v", source.IPNet, source.IfName) }

func (a SNATSources) Len() int           { return len(a) }
func (a SNATSources) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a SNATSources) Less(i, j int) bool { return strings.Compare(a[i].String(), a[j].String()) < 0 }

func (srcs *SNATSources) Sort() SNATSources {
	sort.Sort(*srcs)
	return *srcs
}
func (srcs SNATSources) String() string {
	return fmt.Sprintf("%v", ([]SNATSource)(srcs))
}

func (dnat DNAT) GetPos() string {
	return dnat.NATTo.String()
}

func (snat SNAT) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	compareTo, ok := compareToI.(SNAT)
	if !ok {
		compareToPtr := compareToI.(*SNAT)
		compareTo = *compareToPtr
	}
	if snat.Sources.String() != compareTo.Sources.String() {
		return false
	}
	if snat.NATTo.String() != compareTo.NATTo.String() {
		return false
	}
	if snat.FWSMGlobalId != compareTo.FWSMGlobalId {
		return false
	}
	return true
}

func (dnat DNAT) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	compareTo, ok := compareToI.(DNAT)
	if !ok {
		compareToPtr := compareToI.(*DNAT)
		compareTo = *compareToPtr
	}
	if dnat.Destinations.String() != compareTo.Destinations.String() {
		return false
	}
	if dnat.NATTo.String() != compareTo.NATTo.String() {
		return false
	}
	if dnat.IfName != compareTo.IfName {
		return false
	}
	return true
}

func (snat SNAT) KeyStringValue() string {
	return fmt.Sprintf("%v", snat.Sources.Sort())
}
func (dnat DNAT) KeyStringValue() string {
	return fmt.Sprintf("%v", dnat.Destinations.Sort())
}
