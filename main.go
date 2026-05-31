package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"io"
	"os"
	"encoding/binary"
)


func main() {
	port := flag.Int("port", 1080, "port to listen on")
	flag.Parse()

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen on port %d: %v", *port, err)
	}
	defer listener.Close()

	log.Printf("SOCKS5 proxy listening on :%d", *port)

	for {
		conn, err := listener.Accept()
		if err != nil {
			log.Printf("accept error: %v", err)
			continue
		}
		go handleConnection(conn)
	}
}
func handleConnection(conn net.Conn) {
	defer conn.Close()

	buf := make([]byte, 262)
    n, err := conn.Read(buf)
    if err != nil || n < 2 {
	    return
    }
    
    user := os.Getenv("PROXY_USER")
pass := os.Getenv("PROXY_PASS")
needAuth := user != ""

methodsCount := int(buf[1])

supported := false
selectedMethod := byte(0xFF)

for i := 0; i < methodsCount; i++ {
	if needAuth && buf[2+i] == 0x02 {
		supported = true
		selectedMethod = 0x02
		break
	}
	if !needAuth && buf[2+i] == 0x00 {
		supported = true
		selectedMethod = 0x00
		break
	}
}

if !supported {
	conn.Write([]byte{0x05, 0xFF})
	return
}

conn.Write([]byte{0x05, selectedMethod})

if needAuth {
	n, err = conn.Read(buf)
	if err != nil || n < 3 {
		return
	}

	ulen := int(buf[1])
	username := string(buf[2 : 2+ulen])

	plenIndex := 2 + ulen
	plen := int(buf[plenIndex])
	password := string(buf[plenIndex+1 : plenIndex+1+plen])

	if username != user || password != pass {
		conn.Write([]byte{0x01, 0x01})
		return
	}

	conn.Write([]byte{0x01, 0x00})
}
 
	n, err = conn.Read(buf)
	if err != nil || n < 7 {
		return
	}

	// لازم يكون CONNECT
	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	atyp := buf[3]
	pos := 4
	var host string

	if atyp == 0x01 { // IPv4
		host = net.IP(buf[pos : pos+4]).String()
		pos += 4
	} else if atyp == 0x03 { // Domain
		length := int(buf[pos])
		pos++
		host = string(buf[pos : pos+length])
		pos += length
	} else {
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

    port := int(binary.BigEndian.Uint16(buf[pos : pos+2]))
    targetAddress := fmt.Sprintf("%s:%d", host, port)

	target, err := net.Dial("tcp", targetAddress)
	if err != nil {
		
		conn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer target.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})

	go func() {
	io.Copy(target, conn)
	if tcp, ok := target.(*net.TCPConn); ok {
		tcp.CloseWrite()
	}
}()

io.Copy(conn, target)
if tcp, ok := conn.(*net.TCPConn); ok {
	tcp.CloseWrite()
}
}
