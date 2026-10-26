package internal

import (
	"errors"
	"log"
	"syscall"
	"time"
)

// isTransient reports errors where Accept/ReadFrom should be retried, not treated as fatal.
func isTransient(err error) bool {
	for _, e := range []error{syscall.EMFILE, syscall.ENFILE, syscall.ECONNABORTED, syscall.ENOBUFS, syscall.ENOMEM} {
		if errors.Is(err, e) {
			return true
		}
	}
	return false
}

// retryTransient logs and pauses briefly; callers then continue their loop.
func retryTransient(what string, err error) {
	log.Printf("%s: transient error, retrying: %v", what, err)
	time.Sleep(50 * time.Millisecond)
}
