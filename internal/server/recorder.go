package server

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"k8s.io/klog/v2"
)

type Middleware func(http.Handler) http.Handler

// Apply wraps a list of middlewares around a handler and returns it
func Apply(h http.Handler, middlewares ...Middleware) http.Handler {
	for _, adapter := range middlewares {
		h = adapter(h)
	}
	return h
}

func RecordRequest(recordingDir string) Middleware {
	fi, err := os.Stat(recordingDir)
	if err != nil && !os.IsNotExist(err) {
		klog.Fatalf("Unable to open recording dir: %v", err)
	} else if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(recordingDir, 0644)
		if err != nil {
			klog.Fatalf("Unable to create recording dir: %v", err)
		}
	} else if !fi.IsDir() {
		klog.Fatalf("Recording directory is not a directory: %s", recordingDir)
	}
	return func(h http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if r.Body == nil {
					return
				}
				filename := filepath.Join(
					recordingDir,
					fmt.Sprintf(
						"req-%s-%d.json",
						filepath.Base(r.URL.Path),
						time.Now().UnixNano()))
				f, err := os.OpenFile(filename, os.O_CREATE|os.O_WRONLY, 0666)
				if err != nil {
					klog.ErrorS(err, "Failed to open file", "filename", filename)
					return
				}
				defer f.Close()      //nolint:all
				defer r.Body.Close() //nolint:all
				_, err = io.Copy(f, r.Body)
				if err != nil {
					klog.ErrorS(err, "Failed to write request", "filename", filename)
				}
				klog.V(8).InfoS("Recorded request", "filename", filename)
			}()
			h.ServeHTTP(w, r)
		})
	}
}
