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

type setSlicer interface {
	SetSliceI(interface{})
}

func setDiffMapByOneField(diff *StateDiff, newState State, oldState State, paramName string) {
	newStateV := reflect.ValueOf(newState)
	oldStateV := reflect.ValueOf(oldState)

	map0 := newStateV.FieldByName(paramName)
	map1 := oldStateV.FieldByName(paramName)

	slice0 := reflect.ValueOf(handySlices.MapToSlice(map0.Interface()))
	slice1 := reflect.ValueOf(handySlices.MapToSlice(map1.Interface()))

	added := handySlices.GetSubtraction(slice0.Interface(), slice1.Interface())
	reflect.ValueOf(&diff.Added).Elem().FieldByName(paramName).Addr().Interface().(setSlicer).SetSliceI(added)

	removed := handySlices.GetSubtraction(slice1.Interface(), slice0.Interface())
	reflect.ValueOf(&diff.Removed).Elem().FieldByName(paramName).Addr().Interface().(setSlicer).SetSliceI(removed)

	updated := handySlices.GetDiffedIntersection(slice0.Interface(), slice1.Interface())
	reflect.ValueOf(&diff.Updated).Elem().FieldByName(paramName).Addr().Interface().(setSlicer).SetSliceI(updated)
}

func setDiffSliceByOneField(diff *StateDiff, newState State, oldState State, paramName string) {
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
		switch stateV.Field(i).Kind() {
		case reflect.Map:
			setDiffMapByOneField(&diff, newState, oldState, stateV.Type().Field(i).Name)
		case reflect.Slice:
			setDiffSliceByOneField(&diff, newState, oldState, stateV.Type().Field(i).Name)
		}
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
func (state *State) CopyIgnoredFrom(source State) {
	if state.BridgedVLANs == nil {
		state.BridgedVLANs = VLANs{}
	}
	for k, v := range source.BridgedVLANs {
		if !v.IsIgnored {
			continue
		}
		state.BridgedVLANs[k] = v
	}
}

type StateDiff struct {
	Added   State
	Updated State
	Removed State
}
