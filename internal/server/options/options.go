package options

import (
	"net"
	"time"

	apiserveroptions "k8s.io/apiserver/pkg/server/options"
	cliflag "k8s.io/component-base/cli/flag"
	netutils "k8s.io/utils/net"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/config"
)

const (
	// CedarAuthorizerPolicyDir is the location for all the policy, access entry and policy association files
	CedarAuthorizerPolicyDir                = "/cedar-authorizer/policies"
	CedarAuthorizerPolicyDirRefreshInterval = time.Minute

	// CedarAuthorizerIdentityName is the name of the authorizer's own identity
	CedarAuthorizerIdentityName = "system:authorizer:cedar-authorizer"
	// CedarAuthorizerPairName is the filename of the (optionally pre-generated) certs
	CedarAuthorizerPairName = "cedar-authorizer-server"
	// CedarAuthorizerDefaultCertDir is the default location for the authorizer to store certs
	CedarAuthorizerDefaultCertDir = "/var/run/cedar-authorizer/certs"
	// CedarAuthorizerPublicAddress is the hostname used for certificates
	CedarAuthorizerPublicAddress = "cedar-authorizer"

	// CedarAuthorizerDefaultPort is the default port for the Authorizer server to bind to
	CedarAuthorizerDefaultPort = 10288
	// CedarAuthorizerMetricsPort is the port for the Authorizer metrics and healthz server to bind to
	CedarAuthorizerMetricsPort = 10289
	// CedarAuthorizerDefaultAddress is the default bind address for the Authorizer server
	CedarAuthorizerDefaultAddress = "127.0.0.1"
	// CedarAuthorizerDefaultArtificialErrorRate is the default maximum rate of errors returned per second from the authorizer when --artificial-error-rate is specified.
	CedarAuthorizerDefaultArtificialErrorRate = 5.0
	// CedarAuthorizerDefaultArtificialDenyRate is the default maximum rate of denies returned per second from the authorizer when --artificial-deny-rate is specified.
	CedarAuthorizerDefaultArtificialDenyRate = 5.0
	// CedarAuthorizerShutdownTimeout is how long until the server shuts down
	CedarAuthorizerShutdownTimeout = 10
)

// AuthorizerOptions follows the k8s convention of separating options/flags from config
type AuthorizerOptions struct {
	ShutdownTimeout int

	SecureServing  *apiserveroptions.SecureServingOptions
	ErrorInjection *ErrorInjectionOptions
	Cedar          *CedarOptions
}

type CedarOptions struct {
	PolicyDir                 string
	PolicyDirRrefreshInterval time.Duration
}

type ErrorInjectionOptions struct {
	// ArtificialErrorRate is the maximum number of fake errors returned per second by the error injector
	ArtificialErrorRate float64
	// ArtificialDenyRate is the maximum number of fake denies returned per second by the error injector
	ArtificialDenyRate         float64
	ConfirmNonProdInjectErrors bool
}

// NewCedarAuthorizerOptions creates an CedarAuthorizerOptions
func NewCedarAuthorizerOptions() *AuthorizerOptions {
	return &AuthorizerOptions{
		ShutdownTimeout: CedarAuthorizerShutdownTimeout,
		SecureServing:   NewAuthorizerSecureServingOptions(),
		ErrorInjection:  NewErrorInjectionOptions(),
		Cedar:           NewCedarOptions(),
	}
}

// NewAuthorizerSecureServingOptions creates a SecureServingOptions with some defaults
func NewAuthorizerSecureServingOptions() *apiserveroptions.SecureServingOptions {
	return &apiserveroptions.SecureServingOptions{
		BindAddress: netutils.ParseIPSloppy(CedarAuthorizerDefaultAddress),
		BindPort:    CedarAuthorizerDefaultPort,
		ServerCert: apiserveroptions.GeneratableKeyCert{
			PairName:      CedarAuthorizerPairName,
			CertDirectory: CedarAuthorizerDefaultCertDir,
		},
	}
}

// NewErrorInjectionOptions creates a ErrorInjectionOptions with some defaults
func NewErrorInjectionOptions() *ErrorInjectionOptions {
	return &ErrorInjectionOptions{
		ArtificialErrorRate:        CedarAuthorizerDefaultArtificialErrorRate,
		ArtificialDenyRate:         CedarAuthorizerDefaultArtificialDenyRate,
		ConfirmNonProdInjectErrors: false,
	}
}

func NewCedarOptions() *CedarOptions {
	return &CedarOptions{
		PolicyDir:                 CedarAuthorizerPolicyDir,
		PolicyDirRrefreshInterval: CedarAuthorizerPolicyDirRefreshInterval,
	}
}

// Config creates a runtime config object from the options (command line flags).
func (o *AuthorizerOptions) Config() (*config.AuthorizationWebhookConfig, error) {
	// If we ever need to listen on non-localhost, provide the address here
	alternateDNS, alternateIPs := []string{}, []net.IP{}
	if err := o.SecureServing.MaybeDefaultWithSelfSignedCerts(CedarAuthorizerPublicAddress, alternateDNS, alternateIPs); err != nil {
		return nil, err
	}

	cfg := &config.AuthorizationWebhookConfig{}
	if err := o.ApplyTo(cfg); err != nil {
		return nil, err
	}

	return cfg, nil
}

// ApplyTo converts command line options into runtime config for the Authorizer
func (o *AuthorizerOptions) ApplyTo(cfg *config.AuthorizationWebhookConfig) error {
	if o == nil {
		return nil
	}

	cfg.ShutdownTimeout = o.ShutdownTimeout

	if err := o.SecureServing.ApplyTo(&cfg.SecureServing); err != nil {
		return err
	}

	o.ErrorInjection.ApplyTo(&cfg.ErrorInjection)

	cfg.PolicyDir = o.Cedar.PolicyDir
	cfg.PolicyDirRefreshInterval = o.Cedar.PolicyDirRrefreshInterval

	return nil
}

// ApplyTo converts command line options into runtime config for the Authorizer
func (o *ErrorInjectionOptions) ApplyTo(cfg **config.ErrorInjectionConfig) {
	if o == nil {
		return
	}
	if o.ConfirmNonProdInjectErrors {
		*cfg = &config.ErrorInjectionConfig{
			ArtificialErrorRate: o.ArtificialErrorRate,
			ArtificialDenyRate:  o.ArtificialDenyRate,
			Enabled:             true,
		}
	} else {
		*cfg = &config.ErrorInjectionConfig{
			ArtificialErrorRate: 0,
			ArtificialDenyRate:  0,
			Enabled:             false,
		}
	}
}

// Flags adds flags to fs and binds them to the CedarAuthorizerOptions
func (o *AuthorizerOptions) Flags() *cliflag.NamedFlagSets {
	fss := cliflag.NamedFlagSets{}

	fs := fss.FlagSet("cedar")
	fs.StringVar(&o.Cedar.PolicyDir, "policies-directory", o.Cedar.PolicyDir, "The directory containing Cedar policy files ending in .cedar")
	fs.DurationVar(&o.Cedar.PolicyDirRrefreshInterval, "policies-directory-refresh-interval", o.Cedar.PolicyDirRrefreshInterval, "The interval at which to reread the policy directory")

	fs = fss.FlagSet("runtime")
	fs.IntVar(&o.ShutdownTimeout, "shutdown-timeout", o.ShutdownTimeout, "The length of time to wait between stopCh being closed and server shutdown being triggered.")

	fs = fss.FlagSet("gameday")
	fs.BoolVar(&o.ErrorInjection.ConfirmNonProdInjectErrors, "confirm-non-prod-inject-errors", false, "Confirm that you are operating in a non production environment and you want to inject artificial errors or denies into authorizer responses when it normally wouldn't")
	fs.Float64Var(&o.ErrorInjection.ArtificialErrorRate, "artificial-error-rate", o.ErrorInjection.ArtificialErrorRate, "Cause the authorizer to occasionally return errors at the specified rate.  Useful to validate metrics are working as expected.")
	fs.Float64Var(&o.ErrorInjection.ArtificialDenyRate, "artificial-deny-rate", o.ErrorInjection.ArtificialDenyRate, "Cause the authorizer to occasionally return denies at the specified rate.  Useful to validate metrics are working as expected.")

	o.SecureServing.AddFlags(fss.FlagSet("secure serving"))

	return &fss
}
