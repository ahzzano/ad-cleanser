package internal

import (
	"log"
	"net"
	"sync"
)

type Job struct {
	addr  net.Addr
	query []byte
}

type Handler func(Job) error

type SocketPool struct {
	pool    chan Job
	handler Handler
	wg      sync.WaitGroup
}

func NewSocketPool(workers, queueSize int, h Handler) *SocketPool {
	p := &SocketPool{
		pool:    make(chan Job, queueSize),
		handler: h,
	}

	p.wg.Add(workers)
	for range workers {
		go p.work()
	}
	return p
}

func (s *SocketPool) work() {
	defer s.wg.Done()
	for j := range s.pool {
		s.execJob(j)
	}
}

func (s *SocketPool) execJob(j Job) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("Worker panic: %v", r)
		}
	}()
	if err := s.handler(j); err != nil {
		log.Printf("Error: %v", err.Error())
	}
}

func (s *SocketPool) ProcessRequest(j Job) bool {
	select {
	case s.pool <- j:
		return true
	default:
		return false
	}
}

func (s *SocketPool) Close() {
	close(s.pool)
	s.wg.Wait()
}
