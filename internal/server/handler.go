package server

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httputil"
	"strings"
	"time"

	"github.com/google/uuid"
	authzv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/fields"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/selection"
	utilerrors "k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/apiserver/pkg/authentication/user"
	k8sauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
	"k8s.io/component-base/metrics/legacyregistry"
	"k8s.io/klog/v2"

	cedarauthorizer "github.com/awslabs/cedar-access-control-for-k8s/internal/server/authorizer"
	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/config"
	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/metrics"
	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/options"
)

// AuthorizerServer is contains the authorization handler
type AuthorizerServer struct {
	handler    http.Handler
	authorizer cedarauthorizer.Authorizer
}

// NewServer is a constructor for the AuthorizerServer.  It defines the
// /authorize handler.
func NewServer(authorizer cedarauthorizer.Authorizer, admissionHandler http.Handler, cfg *config.AuthorizationWebhookConfig) *AuthorizerServer {
	mux := http.NewServeMux()
	errorInjector := NewErrorInjector(cfg.ErrorInjection)
	mux.HandleFunc("/v1/authorize", authorizeHandlerFunc(authorizer, errorInjector))
	mux.Handle("/v1/admit", admissionHandler)
	return &AuthorizerServer{
		handler:    mux,
		authorizer: authorizer,
	}
}

func newServer() *http.ServeMux {
	mux := http.NewServeMux()
	// TODO: actually check health status
	mux.HandleFunc("/healthz", healthzHandlerFunc())
	mux.HandleFunc("/readyz", healthzHandlerFunc())
	mux.Handle("/metrics", legacyregistry.Handler())
	return mux
}

// NewMetrics returns a new metrics server.
func NewMetricsServer() *http.Server {
	return &http.Server{
		Addr:         fmt.Sprintf("%s:%d", options.CedarAuthorizerDefaultAddress, options.CedarAuthorizerMetricsPort),
		Handler:      newServer(),
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 5 * time.Second,
	}
}

func authorizeHandlerFunc(authorizer cedarauthorizer.Authorizer, errorInjector *ErrorInjector) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var (
			err                   error
			reason                string
			authorizationDecision k8sauthorizer.Decision
		)
		ctx := r.Context()
		start := time.Now()
		requestId := uuid.New().String()

		defer func() {
			latency := time.Since(start)

			if authorizationDecision != 0 {
				metrics.RecordRequestTotal(ctx, authorizationDecisionString(authorizationDecision))
				metrics.RecordRequestLatency(ctx, authorizationDecisionString(authorizationDecision), latency.Seconds())
				return
			}

			if err != nil {
				metrics.RecordRequestTotal(ctx, "<error>")
				metrics.RecordRequestLatency(ctx, "<error>", latency.Seconds())
			}
		}()

		sar := authzv1.SubjectAccessReview{}

		klogV := klog.V(5)
		if klogV.Enabled() {
			if reqDump, err := httputil.DumpRequest(r, true); err != nil {
				klogV.ErrorS(err, "Failed to dump http request")
			} else {
				klogV.InfoS("Request received", "requestId", requestId, "request", string(reqDump))
			}
		}

		err = json.NewDecoder(r.Body).Decode(&sar)
		if err != nil {
			writeResponse(w, requestId, fmt.Errorf("failed parsing request body: %w", err), k8sauthorizer.DecisionNoOpinion, "Encountered decoding error")
			return
		}

		sarJson, _ := json.Marshal(sar)
		klog.V(11).Infof("SubjectAccessReview JSON: %s", string(sarJson))

		attributes := GetAuthorizerAttributes(sar)
		authorizationDecision, reason, err = errorInjector.InjectIfEnabled(authorizer.Authorize(r.Context(), attributes))
		writeResponse(w, requestId, err, authorizationDecision, reason)
	}
}

func healthzHandlerFunc() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}
}

// GetHandler returns the HTTP handler
func (e *AuthorizerServer) GetHandler() http.Handler {
	return e.handler
}

func writeResponse(w http.ResponseWriter, requestId string, err error, decision k8sauthorizer.Decision, reason string) {
	w.Header().Set("Content-Type", "application/json")

	resp := authzv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Status: authzv1.SubjectAccessReviewStatus{
			Allowed: decision == k8sauthorizer.DecisionAllow,
			Denied:  decision == k8sauthorizer.DecisionDeny,
			Reason:  reason,
		},
	}

	if err != nil {
		resp.Status.EvaluationError = err.Error()
	}

	klog.InfoS("Response", "requestId", requestId, "decision", authorizationDecisionString(decision), "response", resp)

	if err = json.NewEncoder(w).Encode(resp); err != nil {
		panic(err)
	}
}

func authorizationDecisionString(decision k8sauthorizer.Decision) string {
	switch decision {
	case k8sauthorizer.DecisionDeny:
		return "Deny"
	case k8sauthorizer.DecisionAllow:
		return "Allow"
	case k8sauthorizer.DecisionNoOpinion:
		return "NoOpinion"
	}
	return "unknown"
}

// GetAuthorizerAttributes converts a SubjectAccessReview into an Attributes object
func GetAuthorizerAttributes(sar authzv1.SubjectAccessReview) k8sauthorizer.Attributes {
	attributes := k8sauthorizer.AttributesRecord{}

	attributes.User = &user.DefaultInfo{
		Name:   sar.Spec.User,
		Groups: sar.Spec.Groups,
		Extra:  convertExtraForAuthorizerAttributes(sar.Spec.Extra),
		UID:    sar.Spec.UID,
	}
	if sar.Spec.ResourceAttributes != nil {
		attributes.Verb = sar.Spec.ResourceAttributes.Verb
		attributes.Namespace = sar.Spec.ResourceAttributes.Namespace
		attributes.APIGroup = sar.Spec.ResourceAttributes.Group
		attributes.APIVersion = sar.Spec.ResourceAttributes.Version
		attributes.Resource = sar.Spec.ResourceAttributes.Resource
		attributes.Subresource = sar.Spec.ResourceAttributes.Subresource
		attributes.Name = sar.Spec.ResourceAttributes.Name
		attributes.ResourceRequest = true
		if sar.Spec.ResourceAttributes.FieldSelector != nil && sar.Spec.ResourceAttributes.FieldSelector.Requirements != nil {
			var err error
			attributes.FieldSelectorRequirements, err = fieldSelectorAsSelector(sar.Spec.ResourceAttributes.FieldSelector.Requirements)
			if err != nil {
				klog.ErrorS(err, "Failed to convert field selector")
			}
		}
		if sar.Spec.ResourceAttributes.LabelSelector != nil && sar.Spec.ResourceAttributes.LabelSelector.Requirements != nil {
			var err error
			attributes.LabelSelectorRequirements, err = labelSelectorAsSelector(sar.Spec.ResourceAttributes.LabelSelector.Requirements)
			if err != nil {
				klog.ErrorS(err, "Failed to convert label selector")
			}
		}
	}
	if sar.Spec.NonResourceAttributes != nil {
		attributes.Path = sar.Spec.NonResourceAttributes.Path
		attributes.ResourceRequest = false
		attributes.Verb = sar.Spec.NonResourceAttributes.Verb
	}

	return attributes
}

func convertExtraForAuthorizerAttributes(apiExtra map[string]authzv1.ExtraValue) map[string][]string {
	var extra map[string][]string
	if apiExtra != nil {
		extra = map[string][]string{}
		for k, v := range apiExtra {
			extra[strings.ToLower(k)] = v
		}
	}
	return extra
}

// TODO: The following conversion is copied from
// https://github.com/kubernetes/kubernetes/blob/v1.31.1/pkg/registry/authorization/util/helpers.go#L83-L171
//
// Once those methods are public, we'll just import

var labelSelectorOpToSelectionOp = map[metav1.LabelSelectorOperator]selection.Operator{
	metav1.LabelSelectorOpIn:           selection.In,
	metav1.LabelSelectorOpNotIn:        selection.NotIn,
	metav1.LabelSelectorOpExists:       selection.Exists,
	metav1.LabelSelectorOpDoesNotExist: selection.DoesNotExist,
}

func labelSelectorAsSelector(requirements []metav1.LabelSelectorRequirement) (labels.Requirements, error) {
	if len(requirements) == 0 {
		return nil, nil
	}
	reqs := make([]labels.Requirement, 0, len(requirements))
	var errs []error
	for _, expr := range requirements {
		op, ok := labelSelectorOpToSelectionOp[expr.Operator]
		if !ok {
			errs = append(errs, fmt.Errorf("%q is not a valid label selector operator", expr.Operator))
			continue
		}
		values := expr.Values
		if len(values) == 0 {
			values = nil
		}
		req, err := labels.NewRequirement(expr.Key, op, values)
		if err != nil {
			errs = append(errs, err)
			continue
		}
		reqs = append(reqs, *req)
	}

	// If this happens, it means all requirements ended up getting skipped.
	// Return nil rather than [].
	if len(reqs) == 0 {
		reqs = nil
	}

	// Return any accumulated errors along with any accumulated requirements, so recognized / valid requirements can be considered by authorization.
	// This is safe because requirements are ANDed together so dropping unknown / invalid ones results in a strictly broader authorization check.
	return labels.Requirements(reqs), utilerrors.NewAggregate(errs)
}

func fieldSelectorAsSelector(requirements []metav1.FieldSelectorRequirement) (fields.Requirements, error) {
	if len(requirements) == 0 {
		return nil, nil
	}

	reqs := make([]fields.Requirement, 0, len(requirements))
	var errs []error
	for _, expr := range requirements {
		if len(expr.Values) > 1 {
			errs = append(errs, fmt.Errorf("fieldSelectors do not yet support multiple values"))
			continue
		}

		switch expr.Operator {
		case metav1.FieldSelectorOpIn:
			if len(expr.Values) != 1 {
				errs = append(errs, fmt.Errorf("fieldSelectors in must have one value"))
				continue
			}
			// when converting to fields.Requirement, use Equals to match how parsed field selectors behave
			reqs = append(reqs, fields.Requirement{Field: expr.Key, Operator: selection.Equals, Value: expr.Values[0]})
		case metav1.FieldSelectorOpNotIn:
			if len(expr.Values) != 1 {
				errs = append(errs, fmt.Errorf("fieldSelectors not in must have one value"))
				continue
			}
			// when converting to fields.Requirement, use NotEquals to match how parsed field selectors behave
			reqs = append(reqs, fields.Requirement{Field: expr.Key, Operator: selection.NotEquals, Value: expr.Values[0]})
		case metav1.FieldSelectorOpExists, metav1.FieldSelectorOpDoesNotExist:
			errs = append(errs, fmt.Errorf("fieldSelectors do not yet support %v", expr.Operator))
			continue
		default:
			errs = append(errs, fmt.Errorf("%q is not a valid field selector operator", expr.Operator))
			continue
		}
	}

	// If this happens, it means all requirements ended up getting skipped.
	// Return nil rather than [].
	if len(reqs) == 0 {
		reqs = nil
	}

	// Return any accumulated errors along with any accumulated requirements, so recognized / valid requirements can be considered by authorization.
	// This is safe because requirements are ANDed together so dropping unknown / invalid ones results in a strictly broader authorization check.
	return fields.Requirements(reqs), utilerrors.NewAggregate(errs)
}
