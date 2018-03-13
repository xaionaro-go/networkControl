package networkControl

import (
	"github.com/xaionaro-go/handySlices"
	"reflect"
)

type State struct {
	DHCP         DHCP
	BridgedVLANs VLANs
	ACLs         ACLs
	SNATs        SNATs
	DNATs        DNATs
	Routes       Routes
}

func setDiffByOneField(diff *StateDiff, newState State, oldState State, paramName string) {
	newStateV := reflect.ValueOf(newState)
	oldStateV := reflect.ValueOf(oldState)

	slice0 := newStateV.FieldByName(paramName)
	slice1 := oldStateV.FieldByName(paramName)

	added := handySlices.GetSubtraction(slice0.Interface(), slice1.Interface())
	reflect.ValueOf(&diff.Added).Elem().FieldByName(paramName).Set(reflect.ValueOf(added))

	removed := handySlices.GetSubtraction(slice1.Interface(), slice0.Interface())
	reflect.ValueOf(&diff.Removed).Elem().FieldByName(paramName).Set(reflect.ValueOf(removed))

	updated := handySlices.GetDiffedIntersection(slice0.Interface(), slice1.Interface())
	reflect.ValueOf(&diff.Updated).Elem().FieldByName(paramName).Set(reflect.ValueOf(updated))
}

func (newState State) Diff(oldState State) (diff StateDiff) {
	stateV := reflect.ValueOf(oldState)
	for i := 0; i < stateV.NumField(); i++ { // foreach all slice fields
		if stateV.Field(i).Kind() != reflect.Slice {
			continue
		}
		setDiffByOneField(&diff, newState, oldState, stateV.Type().Field(i).Name)
	}

	diff.Updated.DHCP = newState.DHCP

	return
}

func (state *State) AddBridgedVLAN(newVLAN VLAN) error {
	if state.BridgedVLANs[newVLAN.Index] != nil {
		return errAlreadyExists
	}
	for _, vlan := range state.BridgedVLANs {
		if newVLAN.Name == vlan.Name {
			return errConflict
		}
	}

	state.BridgedVLANs[newVLAN.Index] = &newVLAN
	return nil
}

func (state *State) RemoveBridgedVLAN(vlanId int) error {
	if state.BridgedVLANs[vlanId] == nil {
		return errNotFound
	}

	state.BridgedVLANs[vlanId] = nil
	return nil
}
func (state State) GetVLAN(vlanId int) VLAN {
	return state.BridgedVLANs.Get(vlanId)
}

type StateDiff struct {
	Added   State
	Updated State
	Removed State
}
