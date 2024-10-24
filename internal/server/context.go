package server

import "context"

// DeriveStopChannel allows us to use a context instead.uses a stop channel
// (artifact from before contexts existed).  SecureServing currently uses a
// stop channel.
func DeriveStopChannel(ctx context.Context) chan struct{} {
	stopCh := make(chan struct{})
	go func() {
		<-ctx.Done()
		close(stopCh)
	}()
	return stopCh
}
