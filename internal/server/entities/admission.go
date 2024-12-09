package entities

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/schema"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	k8sruntime "k8s.io/apimachinery/pkg/runtime"
	utilruntime "k8s.io/apimachinery/pkg/util/runtime"
	"k8s.io/apiserver/pkg/authentication/user"
	"k8s.io/apiserver/pkg/authorization/authorizer"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

const (
	AdmissionActionIDConnect cedartypes.String = `k8s::admission::Action::"connect"`
	AdmissionActionIDCreate  cedartypes.String = `k8s::admission::Action::"create"`
	AdmissionActionIDUpdate  cedartypes.String = `k8s::admission::Action::"update"`
	AdmissionActionIDDelete  cedartypes.String = `k8s::admission::Action::"delete"`
	AdmissionActionIDAll     cedartypes.String = `k8s::admission::Action::"all"`
)

var (
	runtimeScheme = k8sruntime.NewScheme()
)

func init() {
	// Adds all in-tree types from client-go to scheme so we can decode them
	utilruntime.Must(clientgoscheme.AddToScheme(runtimeScheme))
}

func AdmissionActionEntities() []cedartypes.Entity {
	resp := []cedartypes.Entity{{UID: cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: AdmissionActionIDAll}}}
	for _, actionID := range []cedartypes.String{
		AdmissionActionIDConnect,
		AdmissionActionIDCreate,
		AdmissionActionIDUpdate,
		AdmissionActionIDDelete} {
		resp = append(resp, cedartypes.Entity{
			UID:     cedartypes.EntityUID{Type: schema.AdmissionActionEntityType, ID: actionID},
			Parents: cedartypes.NewEntityUIDSet(resp[0].UID),
		})
	}
	return resp
}

// get the principal UID, and all principal entities from the request
func CedarPrincipalEntitesFromAdmissionRequest(req admission.Request) (*cedartypes.EntityUID, cedartypes.EntityMap, error) {
	principalUid, entities := UserToCedarEntity(&UserInfoWrapper{req.UserInfo})
	return &principalUid, entities, nil
}

func CedarActionEntityFromAdmissionRequest(req admission.Request) (cedartypes.EntityUID, error) {
	resp := cedartypes.EntityUID{Type: schema.AdmissionActionEntityType}
	switch req.Operation {
	case "CONNECT":
		resp.ID = schema.AdmissionConnectAction
	case "CREATE":
		resp.ID = schema.AdmissionCreateAction
	case "UPDATE":
		resp.ID = schema.AdmissionUpdateAction
	case "DELETE":
		resp.ID = schema.AdmissionDeleteAction
	default:
		return resp, fmt.Errorf("unsupported operation %s", req.Operation)
	}
	return resp, nil
}

func AdmissionRequestToAuthorizerAttribute(req admission.Request) authorizer.Attributes {
	return &authorizerAttributeWrapper{req}
}

type authorizerAttributeWrapper struct {
	admission.Request
}

var _ authorizer.Attributes = &authorizerAttributeWrapper{}

func (a *authorizerAttributeWrapper) GetResource() string                            { return a.Resource.Resource }
func (a *authorizerAttributeWrapper) GetSubresource() string                         { return a.SubResource }
func (a *authorizerAttributeWrapper) GetAPIGroup() string                            { return a.Resource.Group }
func (a *authorizerAttributeWrapper) GetAPIVersion() string                          { return a.Resource.Version }
func (a *authorizerAttributeWrapper) GetNamespace() string                           { return a.Namespace }
func (a *authorizerAttributeWrapper) GetName() string                                { return a.Name }
func (a *authorizerAttributeWrapper) GetVerb() string                                { return string(a.Operation) }
func (a *authorizerAttributeWrapper) GetUser() user.Info                             { return &UserInfoWrapper{a.UserInfo} }
func (a *authorizerAttributeWrapper) IsResourceRequest() bool                        { return true }
func (a *authorizerAttributeWrapper) IsReadOnly() bool                               { return false }
func (a *authorizerAttributeWrapper) GetPath() string                                { return "" }
func (a *authorizerAttributeWrapper) GetFieldSelector() (fields.Requirements, error) { return nil, nil }
func (a *authorizerAttributeWrapper) GetLabelSelector() (labels.Requirements, error) { return nil, nil }

func UnstructuredFromAdmissionRequestObject(data []byte) (*unstructured.Unstructured, error) {
	if data == nil {
		return nil, errors.New("unstructured data is nil")
	}
	obj := &unstructured.Unstructured{}

	err := obj.UnmarshalJSON(data)
	if err != nil {
		return nil, fmt.Errorf("error decoding generator resource %w", err)
	}
	return obj, nil
}

func CedarResourceEntityFromAdmissionRequest(req admission.Request) (*cedartypes.Entity, []cedartypes.Entity, error) {
	return cedarResourceEntityFromAdmissionRequest(req, req.Object.Raw)
}

func CedarOldResourceEntityFromAdmissionRequest(req admission.Request) (*cedartypes.Entity, []cedartypes.Entity, error) {
	return cedarResourceEntityFromAdmissionRequest(req, req.OldObject.Raw)
}

func cedarResourceEntityFromAdmissionRequest(req admission.Request, rawData []byte) (*cedartypes.Entity, []cedartypes.Entity, error) {
	// Convert the request's generator resource to unstructured for expansion
	obj, err := UnstructuredFromAdmissionRequestObject(rawData)
	if err != nil {
		return nil, nil, fmt.Errorf("error getting unstructured resource %s: %w", req.Name, err)
	}

	// TODO: entity list construction based on the schema
	// * Generate the schema
	// * Update the schema on CRD changes
	// * Walk the schema for this type and build the Cedar entity

	resourceGroup := req.Resource.Group
	if resourceGroup == "" {
		resourceGroup = "core"
	}

	cedarResourceType := strings.Join([]string{resourceGroup, req.Kind.Version, req.Kind.Kind}, "::")
	identifier := ResourceRequestToPath(AdmissionRequestToAuthorizerAttribute(req))
	resp := cedartypes.Entity{
		UID: cedartypes.NewEntityUID(cedartypes.EntityType(cedarResourceType), cedartypes.String(identifier)),
	}
	attributes, extraEntities, err := UnstructuredToRecord(obj, identifier, resourceGroup, req.Kind.Version, req.Kind.Kind)
	if err != nil {
		return nil, nil, fmt.Errorf("error converting unstructured object to Cedar entity: %w", err)
	}
	resp.Attributes = attributes

	return &resp, extraEntities, nil
}

func UnstructuredToRecord(obj *unstructured.Unstructured, identifier, group, version, kind string) (cedartypes.Record, []cedartypes.Entity, error) {
	if obj == nil {
		return cedartypes.NewRecord(nil), nil, errors.New("unstructured object is nil")
	}
	entities := []cedartypes.Entity{}
	attributes := map[cedartypes.String]cedartypes.Value{}
	for k, v := range obj.Object {
		if v == nil {
			// skip empty values
			continue
		}
		// Try not to blow the stack, limit CRDs to 32 fields deep
		val, nestedEntities, err := walkObject(32, identifier, group, version, kind, k, v)
		if err != nil {
			return cedartypes.NewRecord(nil), nil, err
		}
		if val == nil {
			// skip empty return values, such as empty objects
			continue
		}
		if len(nestedEntities) > 0 {
			entities = append(entities, nestedEntities...)
		}
		attributes[cedartypes.String(k)] = val
	}
	return cedartypes.NewRecord(cedartypes.RecordMap(attributes)), entities, nil
}

func walkObject(i int, identifier, group, version, kind, keyName string, obj any) (cedartypes.Value, []cedartypes.Entity, error) {
	if i == 0 {
		return nil, nil, errors.New("max depth reached")
	}
	if obj == nil {
		// skip empty values
		return nil, nil, nil
	}

	// g/v/k/attrNames
	knownKeyValueStringMapAttributes := map[string]map[string]map[string][]string{
		"core": {
			"v1": {
				"ConfigMap":                   {"data", "binaryData"},
				"CSIPersistentVolumeSource":   {"volumeAttributes"},
				"CSIVolumeSource":             {"volumeAttributes"},
				"FlexPersistentVolumeSource":  {"options"},
				"FlexVolumeSource":            {"options"},
				"PersistentVolumeClaimStatus": {"allocatedResourceStatuses"},
				"Pod":                         {"nodeSelector"},
				"ReplicationController":       {"selector"},
				"Secret":                      {"data", "stringData"},
				"Service":                     {"selector"},
				// The following types only get evaulated if we walk the schema tree
				// "PodSpec":                     {"nodeSelector"},
				// "ReplicationControllerSpec":   {"selector"},
				// "ServiceSpec":                 {"selector"},
			},
		},
		"discovery": {"v1": {"Endpoint": {"deprecatedTopology"}}},
		"node":      {"v1": {"Scheduling": {"nodeSelectors"}}},
		"storage": {
			"v1": {
				"StorageClass":           {"parameters"},
				"VolumeAttachmentStatus": {"attachmentMetadata"},
			},
		},
		// TODO: the following only works once we walk the schema tree
		"meta": {
			"v1": {
				"LabelSelector": {"matchLabels"},
				"ObjectMeta":    {"annotations", "labels"},
			},
		},
	}
	if apiGroup, ok := knownKeyValueStringMapAttributes[group]; ok {
		if apiVersion, ok := apiGroup[version]; ok {
			if attrNames, ok := apiVersion[kind]; ok {
				if slices.Contains(attrNames, keyName) {
					kvEntity := cedartypes.Entity{
						UID: cedartypes.EntityUID{
							Type: schema.MetaV1KeyValueEntity,
							ID:   cedartypes.String(fmt.Sprintf("%s#%s", identifier, keyName)),
						},
					}

					tags := cedartypes.RecordMap{}
					for kk, vv := range obj.(map[string]interface{}) {
						val, ok := vv.(string)
						if !ok {
							klog.ErrorS(nil, "Error converting key/value to string/string", "key", kk, "value", vv)
							break
						}
						tags[cedartypes.String(kk)] = cedartypes.String(val)
					}
					if len(tags) == 0 {
						return nil, nil, nil
					}
					kvEntity.Tags = cedartypes.NewRecord(tags)
					return cedartypes.NewEntityUID(schema.MetaV1KeyValueEntity, kvEntity.UID.ID), []cedartypes.Entity{kvEntity}, nil
				}
			}
		}
	}

	knownKeyValueStringSliceMapAttributes := map[string]map[string]map[string][]string{
		"authentication": {
			"v1": {
				"UserInfo": {"extra"},
			},
		},
		"authorization": {
			"v1": {
				"SubjectAccessReview": {"extra"},
			},
		},
		"certificates": {
			"v1": {
				"CertificateSigningRequest": {"extra"},
			},
		},
	}
	if apiGroup, ok := knownKeyValueStringSliceMapAttributes[group]; ok {
		if apiVersion, ok := apiGroup[version]; ok {
			if attrNames, ok := apiVersion[kind]; ok {
				if slices.Contains(attrNames, keyName) {
					kvEntity := cedartypes.Entity{
						UID: cedartypes.EntityUID{
							Type: schema.MetaV1KeyValuesEntity,
							ID:   cedartypes.String(fmt.Sprintf("%s#%s", identifier, keyName)),
						},
					}
					tags := cedartypes.RecordMap{}
					for kk, vv := range obj.(map[string]interface{}) {
						val, ok := vv.([]string)
						if !ok {
							klog.ErrorS(nil, "Error converting key/value to string/slice of string", "key", kk, "value", vv)
							break
						}
						valSet := []cedartypes.Value{}
						for _, v := range val {
							valSet = append(valSet, cedartypes.String(v))
						}
						tags[cedartypes.String(kk)] = cedartypes.NewSet(valSet...)
					}
					if len(tags) == 0 {
						return nil, nil, nil
					}
					kvEntity.Tags = cedartypes.NewRecord(tags)
					return cedartypes.NewEntityUID(schema.MetaV1KeyValueEntity, kvEntity.UID.ID), []cedartypes.Entity{kvEntity}, nil
				}
			}
		}
	}

	if _, ok := obj.(map[string]interface{}); (keyName == "labels" || keyName == "annotations") && ok {
		kvEntity := cedartypes.Entity{
			UID: cedartypes.EntityUID{
				Type: schema.MetaV1KeyValueEntity,
				ID:   cedartypes.String(fmt.Sprintf("%s#%s", identifier, keyName)),
			},
		}

		tags := cedartypes.RecordMap{}
		for kk, vv := range obj.(map[string]interface{}) {
			val, ok := vv.(string)
			if !ok {
				klog.ErrorS(nil, "Error converting key/value to string/string", "key", kk, "value", vv)
				break
			}
			tags[cedartypes.String(kk)] = cedartypes.String(val)
		}
		if len(tags) == 0 {
			return nil, nil, nil
		}
		kvEntity.Tags = cedartypes.NewRecord(tags)
		return cedartypes.NewEntityUID(schema.MetaV1KeyValueEntity, kvEntity.UID.ID), []cedartypes.Entity{kvEntity}, nil
	}
	// End gross hack for key/value maps
	respEntities := []cedartypes.Entity{}
	switch t := obj.(type) {
	case map[string]interface{}:
		rec := cedartypes.RecordMap{}
		for kk, vv := range obj.(map[string]interface{}) {
			// var val cedartypes.Value
			// var err error
			val, nestedEntities, err := walkObject(i-1, identifier, group, version, kind, kk, vv)
			if err != nil {
				return nil, nil, err
			}
			if val == nil {
				// skip empty values
				continue
			}
			if len(nestedEntities) > 0 {
				respEntities = append(respEntities, nestedEntities...)
			}
			rec[cedartypes.String(kk)] = val
		}
		if len(rec) == 0 {
			// skip empty records
			return nil, nil, nil
		}
		return cedartypes.NewRecord(rec), respEntities, nil
	case []interface{}:
		set := []cedartypes.Value{}
		for _, item := range obj.([]interface{}) {
			val, nestedEntities, err := walkObject(i-1, identifier, group, version, kind, keyName, item)
			if err != nil {
				return nil, nil, err
			}
			if len(nestedEntities) > 0 {
				respEntities = append(respEntities, nestedEntities...)
			}
			set = append(set, val)
		}
		return cedartypes.NewSet(set...), respEntities, nil
	case string:
		// Try to parse the string as an IP address for
		// known IP address keys
		if slices.Contains([]string{"podIP", "clusterIP", "loadBalancerIP", "hostIP", "ip", "podIPs", "hostIPs"}, keyName) {
			addr, err := cedartypes.ParseIPAddr(obj.(string))
			if err != nil {
				return cedartypes.String(obj.(string)), nil, nil
			}
			return addr, nil, nil
		}
		return cedartypes.String(obj.(string)), nil, nil
	case int:
		return cedartypes.Long(obj.(int)), nil, nil
	case int64:
		return cedartypes.Long(obj.(int64)), nil, nil
	case uint:
		return cedartypes.Long(obj.(uint)), nil, nil
	case uint64:
		return cedartypes.Long(obj.(uint64)), nil, nil
	case bool:
		return cedartypes.Boolean(obj.(bool)), nil, nil
	default:
		return nil, nil, fmt.Errorf("unsupported type %T", t)
	}

}
