package entities

import (
	"strings"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/schema"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	authenticationv1 "k8s.io/api/authentication/v1"
	"k8s.io/apiserver/pkg/authentication/user"
)

type UserInfoWrapper struct {
	authenticationv1.UserInfo
}

var _ user.Info = &UserInfoWrapper{}

func (u *UserInfoWrapper) GetName() string { return u.UserInfo.Username }
func (u *UserInfoWrapper) GetUID() string {
	// set a userID if not present so we can identifiy the user entity
	if u.UserInfo.UID == "" {
		return u.UserInfo.Username
	}
	return u.UserInfo.UID
}
func (u *UserInfoWrapper) GetGroups() []string { return u.UserInfo.Groups }
func (u *UserInfoWrapper) GetExtra() map[string][]string {
	resp := map[string][]string{}
	for k, v := range u.UserInfo.Extra {
		resp[k] = []string(v)
	}
	return resp
}

func UserToCedarEntity(user user.Info) (cedartypes.EntityUID, cedartypes.EntityMap) {
	resp := cedartypes.EntityMap{}

	groupEntityUids := []cedartypes.EntityUID{}

	for _, group := range user.GetGroups() {
		groupEntityUid := cedartypes.EntityUID{
			Type: schema.GroupEntityType,
			ID:   cedartypes.String(group),
		}
		groupEntity := cedartypes.Entity{
			UID: groupEntityUid,
			Attributes: cedartypes.NewRecord(cedartypes.RecordMap(map[cedartypes.String]cedartypes.Value{
				cedartypes.String("name"): cedartypes.String(group),
			})),
		}

		resp[groupEntityUid] = groupEntity
		groupEntityUids = append(groupEntityUids, groupEntityUid)
	}

	attributes := cedartypes.RecordMap(map[cedartypes.String]cedartypes.Value{
		cedartypes.String("name"): cedartypes.String(user.GetName()),
		// Groups field is omitted since we represent groups as entities
	})

	principalEntityType := schema.UserEntityType
	if strings.HasPrefix(user.GetName(), "system:node:") && strings.Count(user.GetName(), ":") == 2 {
		principalEntityType = schema.NodeEntityType
		attributes[cedartypes.String("name")] = cedartypes.String(strings.Split(user.GetName(), ":")[2])
	}

	if strings.HasPrefix(user.GetName(), "system:serviceaccount:") && strings.Count(user.GetName(), ":") == 3 {
		principalEntityType = schema.ServiceAccountEntityType
		parts := strings.Split(user.GetName(), ":")
		attributes[cedartypes.String("namespace")] = cedartypes.String(parts[2])
		attributes[cedartypes.String("name")] = cedartypes.String(parts[3])
	}

	principalUID := cedartypes.EntityUID{
		Type: principalEntityType,
		ID:   cedartypes.String(user.GetUID()),
	}

	principalEntity := cedartypes.Entity{
		UID:     principalUID,
		Parents: cedartypes.NewEntityUIDSet(groupEntityUids...),
	}

	// create extras tag-holding entity
	extrasEntity := cedartypes.Entity{
		UID: cedartypes.EntityUID{
			Type: schema.ExtraValuesEntityType,
			ID:   principalUID.ID + "#extras",
		},
	}

	extraValues := cedartypes.RecordMap{}
	for k, v := range user.GetExtra() {
		extraVV := []cedartypes.Value{}
		for _, vv := range v {
			extraVV = append(extraVV, cedartypes.String(vv))
		}
		extraValues[cedartypes.String(k)] = cedartypes.NewSet(extraVV...)
	}

	// If extras values are present,
	// * set the extra entity's tags
	// * add the tag entity to the response
	// * set the extra entity as the "extra" attr on the principal
	if len(extraValues) > 0 {
		extrasEntity.Tags = cedartypes.NewRecord(extraValues)
		resp[extrasEntity.UID] = extrasEntity
		attributes[cedartypes.String("extra")] = extrasEntity.UID
	}
	principalEntity.Attributes = cedartypes.NewRecord(attributes)
	resp[principalUID] = principalEntity
	return principalUID, resp
}
