package networkControl

import (
	"fmt"
	"github.com/1046102779/slicelement"
	"reflect"
)

type State struct {
	BridgedVLANs VLANs
}


func compareFunc(aI, bI interface{}) bool {
	switch a := aI.(type) {
	case VLAN:
		return a.Index == bI.(VLAN).Index
	}

	panic(fmt.Errorf("This shouldn't happened: %T", aI))
}

func keyField(objsName string) string {
	switch objsName {
	case "BridgedVLANs":
		return "Index"
	}

	panic("This shouldn't happened: <"+objsName+">")
}

func setDiffByOneField(diff *StateDiff, newState State, oldState State, paramName string) {
	newStateV := reflect.ValueOf(newState)
	oldStateV := reflect.ValueOf(oldState)

	slice0 := newStateV.FieldByName(paramName)
	slice1 := oldStateV.FieldByName(paramName)

	added, err := slicelement.GetDifference(slice0.Interface(), slice1.Interface(), keyField(paramName))
	if err != nil {
		panic(err)
	}
	reflect.ValueOf(&diff.Added).Elem().FieldByName(paramName).Set(reflect.ValueOf(added))

	removed, err := slicelement.GetDifference(slice1.Interface(), slice0.Interface(), keyField(paramName))
	if err != nil {
		panic(err)
	}
	reflect.ValueOf(&diff.Removed).Elem().FieldByName(paramName).Set(reflect.ValueOf(removed))

	updated, err := slicelement.GetInteraction(slice0.Interface(), slice1.Interface(), keyField(paramName))
	if err != nil {
		panic(err)
	}
	reflect.ValueOf(&diff.Updated).Elem().FieldByName(paramName).Set(reflect.ValueOf(updated))
}

func (newState State) Diff(oldState State) (diff StateDiff) {
	stateV := reflect.ValueOf(oldState)
	for i := 0; i < stateV.NumField(); i++ { // foreach all fields
		setDiffByOneField(&diff, newState, oldState, stateV.Type().Field(i).Name)
	}

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
