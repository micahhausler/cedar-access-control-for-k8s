package config

import (
	"time"

	apiserver "k8s.io/apiserver/pkg/server"
)

// AuthorizationWebhookConfig contains the runtime config for the authorizer
type AuthorizationWebhookConfig struct {
	ShutdownTimeout int

	PolicyDir                string
	PolicyDirRefreshInterval time.Duration

	ErrorInjection *ErrorInjectionConfig
	SecureServing  *apiserver.SecureServingInfo
}

type ErrorInjectionConfig struct {
	ArtificialErrorRate float64
	ArtificialDenyRate  float64
	Enabled             bool
}
