package store

import (
	"context"

	cedarv1alpha1 "github.com/awslabs/cedar-access-control-for-k8s/api/v1alpha1"
	"github.com/cedar-policy/cedar-go"
	"k8s.io/apimachinery/pkg/runtime"
	uitlruntime "k8s.io/apimachinery/pkg/util/runtime"
)

var (
	scheme *runtime.Scheme = runtime.NewScheme()
)

func init() {
	uitlruntime.Must(cedarv1alpha1.AddToScheme(scheme))
}

type PolicyStore interface {
	// InitalPolicyLoadComplete signals if authorizer is ready to authorize requests
	// While this is false, the authorizer will emit a k8sauthorizer.NoOpinion until its ready
	InitalPolicyLoadComplete() bool
	PolicySet(context.Context) *cedar.PolicySet
}
