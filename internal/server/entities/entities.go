package entities

import (
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

func UnifyEntities(entities ...cedartypes.Entity) cedartypes.EntityMap {
	resp := cedartypes.EntityMap{}
	for _, e := range entities {
		resp[e.UID] = e
	}
	return resp
}

func MergeIntoEntities(base cedartypes.EntityMap, entities ...cedartypes.Entity) {
	for _, e := range entities {
		base[e.UID] = e
	}
}
