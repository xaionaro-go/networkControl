package iptables

import (
	"github.com/xaionaro-go/networkControl"
)

type iptables struct {
	
}

func NewFirewall() networkControl.FirewallI {
	return &iptables{}
}


