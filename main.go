package main

import (
	"io"
	"log"
	"net"
)

func main() {
	tcp, err := net.Listen("tcp", "127.0.0.1:5353")
	if err != nil {
		log.Fatal(err)
	}
	udp, err := net.ListenPacket("udp", "127.0.0.1:5353")
	if err != nil {
		tcp.Close()
		log.Fatal(err)
	}
	log.Print("listening on TCP and UDP 127.0.0.1:5353")
	go func() {
		log.Fatal(serveUDP(udp))
	}()
	log.Fatal(serveTCP(tcp))
}

func serveUDP(conn net.PacketConn) error {
	var buf [65535]byte
	for {
		n, peer, err := conn.ReadFrom(buf[:])
		if err != nil {
			return err
		}
		written, err := conn.WriteTo(buf[:n], peer)
		if err != nil {
			log.Printf("UDP reply: %v", err)
		} else if written != n {
			log.Printf("UDP reply: %v", io.ErrShortWrite)
		}
	}
}

func serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		// shortcut: TCP connections are unbounded, add limits before exposing this server beyond loopback
		go func() {
			defer conn.Close()
			if _, err := io.Copy(conn, conn); err != nil {
				log.Printf("TCP echo: %v", err)
			}
		}()
	}
}
