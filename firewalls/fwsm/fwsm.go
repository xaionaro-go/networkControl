package fwsm

import (
	"github.com/xaionaro-go/networkControl"
)

type fwsm struct {
}

func NewFirewall() networkControl.FirewallI {
	return &fwsm{}
}
