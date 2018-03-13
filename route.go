package networkControl

import (
	"net"
)

type Route struct {
	Sources     IPNets
	Destination IPNet
	Gateway     net.IP
	Metric      int

	// TODO: try to remove this
	IfName string
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
