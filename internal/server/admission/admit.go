package admission

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"

	"github.com/cedar-policy/cedar-go"
	cedartypes "github.com/cedar-policy/cedar-go/types"
	admissionv1 "k8s.io/api/admission/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/klog/v2"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/entities"
	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/store"
)

type cedarHandler struct {
	stores         store.TieredPolicyStores
	allStoresReady bool
	allowOnError   bool
}

var _ admission.Handler = &cedarHandler{}

func NewCedarHandler(stores []store.PolicyStore, allowOnError bool) admission.Handler {
	return &cedarHandler{
		stores:       stores,
		allowOnError: allowOnError,
	}
}

func allowedResponse(uid types.UID) admission.Response {
	resp := admission.Allowed("")
	resp.UID = uid
	return resp
}

func (h *cedarHandler) Handle(ctx context.Context, req admission.Request) admission.Response {
	// for now, skip some namespaces
	if slices.Contains([]string{"kube-system", "cedar-k8s-authz-system"}, req.Namespace) {
		return allowedResponse(req.UID)
	}

	if !h.allStoresReady {
		for i, store := range h.stores {
			if !store.InitalPolicyLoadComplete() {
				klog.V(2).Infof("policy store [%d] (%s) not ready, emitting allow response", i, store.Name())
				return allowedResponse(req.UID)
			}
		}
		h.allStoresReady = true
	}

	allowed, diagnostics, err := h.review(req)
	if err != nil {
		klog.V(3).ErrorS(err, "error during review")
		return admission.Errored(http.StatusInternalServerError, err)
	}
	reasons := []byte{}
	if diagnostics != nil && len(diagnostics.Reasons) > 0 {
		reasons, _ = json.Marshal(diagnostics.Reasons)
	}

	vResp := admission.Response{
		AdmissionResponse: admissionv1.AdmissionResponse{
			UID:     req.UID,
			Allowed: allowed,
			Result: &metav1.Status{
				Code:    http.StatusOK,
				Message: string(reasons),
			},
		},
	}
	return vResp
}

func (h *cedarHandler) review(req admission.Request) (bool, *cedar.Diagnostic, error) {
	if reqJSON, err := json.Marshal(req); err != nil {
		klog.V(8).Info("Reviewing request ", string(reqJSON))
	} else {
		klog.V(8).Infof("Reviewing request: %#v", req)
	}

	principalEntity, requestEntities, err := entities.CedarPrincipalEntitesFromAdmissionRequest(req)
	if err != nil {
		return h.allowOnError, nil, fmt.Errorf("error converting request to Cedar principal entity: %w", err)
	}
	var resourceEntity *cedartypes.Entity

	if req.Operation == "DELETE" {
		resourceEntity, err = entities.CedarOldResourceEntityFromAdmissionRequest(req)
		if err != nil {
			return h.allowOnError, nil, fmt.Errorf("error converting oldObject to Cedar entity: %w", err)
		}
	} else {
		resourceEntity, err = entities.CedarResourceEntityFromAdmissionRequest(req)
		if err != nil {
			return h.allowOnError, nil, fmt.Errorf("error converting request to Cedar resource entity: %w", err)
		}
	}

	var oldObject *cedartypes.Entity
	if req.OldObject.Raw != nil && req.Operation != "DELETE" {
		oldObject, err = entities.CedarOldResourceEntityFromAdmissionRequest(req)
		if err != nil {
			return h.allowOnError, nil, fmt.Errorf("error converting oldObject to Cedar entity: %w", err)
		}

		// The old object and new object will have the same UID, and to differentiate them
		// we use the validation UID (which is unique) as an entity UID for the old object.
		// This makes it impossible to authorize requests directly on the old object's UID,
		// but that's probably fine
		oldObject.UID.ID = cedartypes.String(req.UID)
		attrMap := resourceEntity.Attributes.Map()
		attrMap["oldObject"] = oldObject.UID
		resourceEntity.Attributes = cedartypes.NewRecord(attrMap)
		entities.MergeIntoEntities(requestEntities, *oldObject)
	}

	klog.V(7).InfoS("Admission resource entity", "entity", resourceEntity)
	entities.MergeIntoEntities(requestEntities, *resourceEntity)

	actionEntityUID, err := entities.CedarActionEntityFromAdmissionRequest(req)
	if err != nil {
		return h.allowOnError, nil, fmt.Errorf("error converting request to Cedar action entity: %w", err)
	}

	entities.MergeIntoEntities(requestEntities, entities.AdmissionActionEntities()...)

	context := cedartypes.RecordMap{}
	if oldObject != nil {
		context["oldObject"] = oldObject.Attributes
	}

	klog.V(6).InfoS("Request evaluation input",
		"entities", requestEntities,
		"principal", principalEntity,
		"action", actionEntityUID,
		"resource", resourceEntity.UID,
		"context", context,
	)

	cedarReq := cedartypes.Request{
		Principal: *principalEntity,
		Resource:  resourceEntity.UID,
		Action:    actionEntityUID,
		Context:   cedartypes.NewRecord(context),
	}
	klog.V(9).InfoS("Request evaluation input", "uid", req.UID, "request", cedarReq)
	decision, diagnostics := h.stores.IsAuthorized(requestEntities, cedarReq)
	klog.V(9).InfoS("Policy decision", "uid", req.UID, "decision", decision, "diagnostics", diagnostics)
	if decision == cedar.Deny {
		if len(diagnostics.Reasons) == 0 && len(diagnostics.Errors) == 0 {
			// should never reach this with the always allow policy
			klog.Error("Request denied without reasons, somehow the default permit policy didn't get evaluated")
		}
		klog.V(5).InfoS("Request denied", "uid", req.UID, "diagnostics", diagnostics)
		return false, &diagnostics, nil
	}
	klog.V(5).InfoS("No forbid policies applied, request allowed", "uid", req.UID)
	return true, nil, nil
}
