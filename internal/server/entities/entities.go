package entities

import (
	cedartypes "github.com/cedar-policy/cedar-go/types"
)

func UnifyEntities(entities ...*cedartypes.Entity) cedartypes.Entities {
	resp := cedartypes.Entities{}
	for _, e := range entities {
		resp[e.UID] = e
	}
	return resp
}

func MergeIntoEntities(base cedartypes.Entities, entities ...*cedartypes.Entity) {
	for _, e := range entities {
		base[e.UID] = e
	}
}
