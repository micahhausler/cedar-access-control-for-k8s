package config

import (
	apiserver "k8s.io/apiserver/pkg/server"
)

// AuthorizationWebhookConfig contains the runtime config for the authorizer
type AuthorizationWebhookConfig struct {
	ShutdownTimeout int

	StoreConfig string

	ErrorInjection *ErrorInjectionConfig
	SecureServing  *apiserver.SecureServingInfo

	DebugOptions *DebugOptions
}

type ErrorInjectionConfig struct {
	ArtificialErrorRate float64
	ArtificialDenyRate  float64
	Enabled             bool
}

type DebugOptions struct {
	EnableProfiling bool

	EnableRecording bool
	RecordingDir    string
}
