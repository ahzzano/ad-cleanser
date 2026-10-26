package internal

import (
	"log"
	"sync"
)

// limiter runs at most cap(sem) functions at once; tryGo drops work instead of queueing.
type limiter struct {
	sem chan struct{}
	wg  sync.WaitGroup
}

func newLimiter(n int) *limiter { return &limiter{sem: make(chan struct{}, n)} }

// tryGo runs fn in a goroutine unless the limiter is full, and reports whether it did.
func (l *limiter) tryGo(fn func()) bool {
	select {
	case l.sem <- struct{}{}:
	default:
		return false
	}
	l.wg.Add(1)
	go func() {
		defer l.wg.Done()
		defer func() { <-l.sem }()
		defer func() {
			if r := recover(); r != nil {
				log.Printf("panic: %v", r)
			}
		}()
		fn()
	}()
	return true
}

// wait blocks until all running functions have returned.
func (l *limiter) wait() { l.wg.Wait() }
