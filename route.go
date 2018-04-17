package networkControl

import (
	"fmt"
	"github.com/xaionaro-go/handySlices"
	"net"
)

type Route struct {
	Sources     IPNets
	Destination IPNet
	Gateway     net.IP
	Metric      int
	IfName      string
}

type Routes []*Route

func (a Routes) Len() int           { return len(a) }
func (a Routes) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a Routes) Less(i, j int) bool { return a[i].GetPos() < a[j].GetPos() }

func (route Route) GetPos() string {
	return route.Gateway.String()
}

func (route Route) KeyStringValue() string {
	return route.Destination.String()
}
func (route Route) IsEqualToI(compareToI handySlices.IsEqualToIer) bool {
	compareTo, ok := compareToI.(Route)
	if !ok {
		compareToPtr := compareToI.(*Route)
		compareTo = *compareToPtr
	}

	if !route.Sources.IsEqualTo(compareTo.Sources) {
		fmt.Println("!route.Sources.IsEqualTo(compareTo.Sources)", route.Sources, compareTo.Sources)
		return false
	}
	if !route.Destination.IsEqualTo(compareTo.Destination) {
		fmt.Println("!route.Destination.IsEqualTo(compareTo.Destination)", route.Destination, compareTo.Destination)
		return false
	}
	if fmt.Sprintf("%s", route.Gateway.String()) != fmt.Sprintf("%s", compareTo.Gateway.String()) {
		fmt.Println("route.Gateway.String() != compareTo.String()", route.Gateway, compareTo.Gateway)
		return false
	}
	if route.Metric != compareTo.Metric {
		fmt.Println("route.Metric != compareTo.Metric", route.Metric, compareTo.Metric)
		return false
	}
	if route.IfName != compareTo.IfName {
		fmt.Println("route.IfName != compareTo.IfName", route.IfName, compareTo.IfName)
		return false
	}

	return true
}
