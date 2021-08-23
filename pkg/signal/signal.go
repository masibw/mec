package signal

import (
	"os"
	"os/signal"
)

const signalBufferSize = 2048

// newSignalHandler returns a signal handler for processing SIGCHLD and SIGWINCH signals
// while still forwarding all other signals to the process.
// If notifySocket is present, use it to read systemd notifications from the container and
// forward them to notifySocketHost.
func newSignalHandler(enableSubreaper bool, notifySocket *notifySocket) *signalHandler {
	// ensure that we have a large buffer size so that we do not miss any signals
	// in case we are not processing them fast enough.
	s := make(chan os.Signal, signalBufferSize)
	// handle all signals for the process.
	signal.Notify(s)
	return &signalHandler{
		signals:      s,
		notifySocket: notifySocket,
	}
}

type signalHandler struct {
	signals      chan os.Signal
	notifySocket *notifySocket
}

