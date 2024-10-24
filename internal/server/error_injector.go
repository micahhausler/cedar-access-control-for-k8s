package server

import (
	"errors"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/config"
	"golang.org/x/time/rate"
	k8sauthorizer "k8s.io/apiserver/pkg/authorization/authorizer"
)

type ErrorInjector struct {
	Enabled      bool
	errorLimiter *rate.Limiter
	denyLimiter  *rate.Limiter
}

func NewErrorInjector(cfg *config.ErrorInjectionConfig) *ErrorInjector {
	return &ErrorInjector{
		Enabled:      cfg.Enabled,
		errorLimiter: rate.NewLimiter(rate.Limit(cfg.ArtificialErrorRate), 1),
		denyLimiter:  rate.NewLimiter(rate.Limit(cfg.ArtificialDenyRate), 1),
	}
}

func (ei *ErrorInjector) InjectIfEnabled(decision k8sauthorizer.Decision, reason string, err error) (k8sauthorizer.Decision, string, error) {
	if !ei.Enabled {
		return decision, reason, err
	}

	// TODO: randomize first bucket to check
	if ei.errorLimiter.Allow() {
		decision, reason, err = newFakeError()
	}

	if ei.denyLimiter.Allow() {
		decision, reason, err = newFakeDeny()
	}
	// add errors
	return decision, reason, err
}

func newFakeError() (k8sauthorizer.Decision, string, error) {
	// TODO make this more like real authorizer errors
	return k8sauthorizer.DecisionNoOpinion, "", errors.New("encountered error")
}

func newFakeDeny() (k8sauthorizer.Decision, string, error) {
	// TODO make this more like real authorizer errors
	return k8sauthorizer.DecisionDeny, "Authorization denied", nil
}
