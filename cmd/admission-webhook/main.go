package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"

	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/admission"
	"github.com/awslabs/cedar-access-control-for-k8s/internal/server/store"
	"github.com/cedar-policy/cedar-go"
	"github.com/go-logr/logr"
	"k8s.io/klog/v2"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
	cradmission "sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

func main() {
	klog.InitFlags(nil)
	flag.Parse()

	// TODO: use a unique policy name to not collide with other policies
	crdStore, err := store.NewCRDPolicyStore(cedar.PolicyMap{
		"always-allow": admission.AllowAllAdmissionPolicy(),
	})
	if err != nil {
		klog.Fatalf("Error creating CRD policy store: %v", err)
		os.Exit(1)
	}
	handler := admission.NewCedarHandler(crdStore, true)
	vWebhook := &cradmission.Webhook{Handler: handler}
	webhookServer := webhook.NewServer(webhook.Options{})

	ctrl.SetLogger(logr.FromSlogHandler(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{AddSource: true, Level: slog.LevelDebug})))

	mux := http.NewServeMux()
	checker := healthz.CheckHandler{Checker: healthz.Checker(func(_ *http.Request) error { return nil })}
	mux.Handle("/healthz", &checker)
	mux.Handle("/readyz", &checker)
	go func() {
		if err := http.ListenAndServe(":8081", mux); err != nil {
			klog.Error(err, "error starting healthz server")
			os.Exit(1)
		}
	}()

	webhookServer.Register("/v1/admit", vWebhook)
	if err := webhookServer.Start(ctrl.SetupSignalHandler()); err != nil {
		klog.Error(err, "error starting webhook server")
		os.Exit(1)
	}
}
