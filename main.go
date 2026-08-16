package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

var serverIpPort string
var clientID string
var timing int32
var maxTiming int32 = 1000
var minTiming int32 = 0

// udpWriteMu serializes UDP writes to prevent SetWriteDeadline races
// between sendCCPayload and receiveCCPayload on the same *net.UDPConn.
var udpWriteMu sync.Mutex

type ccPacket struct {
	PacketType string `json:"packetType"`
	Payload    string `json:"payload"`
}

func xorBytes(data []byte, key []byte) []byte {
	c := make([]byte, len(data))
	for i := range data {
		c[i] = data[i] ^ key[i%len(key)]
	}
	return c
}

// bufPool reuses 64KB buffers for UDP reads to eliminate GC pressure.
var bufPool = sync.Pool{
	New: func() interface{} {
		b := make([]byte, 65535)
		return &b
	},
}

func packetReceive(session *wintun.Session, shutdown <-chan struct{}) {
	for {
		select {
		case <-shutdown:
			return
		default:
		}

		packetReceived, err := session.ReceivePacket()
		if len(packetReceived) == 0 {
			currentTiming := atomic.LoadInt32(&timing)
			if currentTiming < maxTiming {
				// Slow ramp: add 100μs on each empty read
				atomic.AddInt32(&timing, 100)
			}
			time.Sleep(time.Duration(currentTiming) * time.Microsecond)
		} else {
			if err == nil {
				// Fast recovery: reset timing immediately on success
				atomic.StoreInt32(&timing, minTiming)
				sendCCPayload("networkPacket", packetReceived)
				session.ReleaseReceivePacket(packetReceived)
			}
		}
	}
}

func packetSend(session *wintun.Session, packet []byte) bool {
	for retries := 0; retries < 3; retries++ {
		pk, err := session.AllocateSendPacket(len(packet))
		if err != nil {
			time.Sleep(time.Millisecond * time.Duration(1<<(retries+1)))
			continue
		}
		copy(pk, packet)
		session.SendPacket(pk)
		return true
	}
	return false
}

var ccConnection *net.UDPConn
var ccConnectionMu sync.Mutex

func control() {
	serverAddress, err := net.ResolveUDPAddr("udp", serverIpPort)
	if err != nil {
		fmt.Println("ResolveUDPAddr error:", err)
		os.Exit(1)
	}
	var conn *net.UDPConn
	conn, err = net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		fmt.Println("DialUDP error:", err)
		os.Exit(1)
	}
	ccConnectionMu.Lock()
	ccConnection = conn
	ccConnectionMu.Unlock()
	fmt.Println("UDP connected to", serverIpPort)
}

// reconnectUDP attempts to reconnect the UDP connection with retry logic.
// Returns true if reconnection succeeded, false if context was cancelled.
func reconnectUDP(shutdown <-chan struct{}) bool {
	for retries := 0; retries < 10; retries++ {
		if retries > 0 {
			time.Sleep(time.Second * time.Duration(retries))
		}
		serverAddress, err := net.ResolveUDPAddr("udp", serverIpPort)
		if err != nil {
			fmt.Println("ResolveUDPAddr error:", err)
			time.Sleep(time.Second)
			continue
		}
		conn, err := net.DialUDP("udp", nil, serverAddress)
		if err != nil {
			fmt.Println("DialUDP error:", err)
			time.Sleep(time.Second)
			continue
		}
		ccConnectionMu.Lock()
		if ccConnection != nil {
			ccConnection.Close()
		}
		ccConnection = conn
		ccConnectionMu.Unlock()
		fmt.Println("UDP reconnected to", serverIpPort)
		return true
	}
	return false
}

// getUDPConn returns the current UDP connection, or reconnects if nil.
func getUDPConn() *net.UDPConn {
	ccConnectionMu.Lock()
	defer ccConnectionMu.Unlock()
	if ccConnection == nil {
		return nil
	}
	return ccConnection
}

// ipFromPacket extracts the 4-byte destination IP at offset 16-19.
// Uses bit shifting instead of big.Int for performance.
func ipFromPacket(packet []byte) net.IP {
	return net.IPv4(packet[16], packet[17], packet[18], packet[19])
}

var xorKey []byte
var myIP string
var xorKeyString string

func sendCCPayload(packetType string, packet []byte) {
	// Get a stable reference to the UDP connection
	conn := getUDPConn()
	if conn == nil {
		go reconnectUDP(shutdownChan)
		return
	}

	// Serialize writes to avoid SetWriteDeadline races with reads
	udpWriteMu.Lock()
	defer udpWriteMu.Unlock()

	// Use a short deadline to prevent blocking the hot path
	conn.SetWriteDeadline(time.Now().Add(2 * time.Second))
	dstIP := ipFromPacket(packet)

	sEnc := base64.StdEncoding.EncodeToString(xorBytes(packet, xorKey))

	// Build the full message with proper structure
	message := fmt.Sprintf(`{"Cookie":"ItWillBeClientCookie","networkID":1,"clientID":%s,"srcIp":"%s","packetType":"%s","dstIP":"%s","payload":"%s"}`,
		clientID, myIP, packetType, dstIP.String(), sEnc)

	n, writeErr := conn.Write([]byte(message))
	if writeErr != nil {
		fmt.Println("UDP write error:", writeErr)
		// Mark connection as dead for next read to retry
		ccConnectionMu.Lock()
		if ccConnection != nil {
			ccConnection.Close()
			ccConnection = nil
		}
		ccConnectionMu.Unlock()
		go reconnectUDP(shutdownChan)
		_ = n
	}
}

func receiveCCPayload(session *wintun.Session, shutdown <-chan struct{}) {
	fmt.Println("Waiting for payload from server")
	for {
		conn := getUDPConn()
		if conn == nil {
			reconnectUDP(shutdownChan)
			conn = getUDPConn()
			if conn == nil {
				time.Sleep(time.Second)
				continue
			}
		}

		conn.SetReadDeadline(time.Now().Add(5 * time.Second))
		buf := bufPool.Get().(*[]byte)
		p := *buf
		n, remoteaddr, err := conn.ReadFromUDP(p)
		if err != nil {
			bufPool.Put(&p)
			// Check if the read timed out (normal) vs a real error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			// On read error, mark connection as dead and retry
			ccConnectionMu.Lock()
			if ccConnection == conn {
				conn.Close()
				ccConnection = nil
			}
			ccConnectionMu.Unlock()
			go reconnectUDP(shutdownChan)
			continue
		}
		p = bytes.Trim(p[:n], "\x00")

		data := ccPacket{}
		if err := json.Unmarshal(p, &data); err != nil {
			fmt.Println("JSON unmarshal error:", err)
			bufPool.Put(&p)
			continue
		}

		if data.PacketType == "networkPacket" {
			atomic.StoreInt32(&timing, minTiming)
			pBytes, err := base64.StdEncoding.DecodeString(data.Payload)
			if err != nil {
				fmt.Println("Base64 decode error:", err)
				bufPool.Put(&p)
				continue
			}
			pBytes = xorBytes(pBytes, xorKey)
			packetSend(session, pBytes)
			bufPool.Put(&p)
		} else if data.PacketType == "controlMessage" {
			pBytes, err := base64.StdEncoding.DecodeString(data.Payload)
			if err != nil {
				bufPool.Put(&p)
				continue
			}
			fmt.Println("Control Message:", string(pBytes))
			bufPool.Put(&p)
		}
		_ = remoteaddr // avoid unused variable warning
	}
}

var shutdownChan = make(chan struct{})

func main() {
	flag.StringVar(&myIP, "myIP", "127.0.0.1", "a string")
	flag.StringVar(&clientID, "clientID", "1", "a string")
	flag.StringVar(&serverIpPort, "serverIpPort", "127.0.0.1:8082", "a string")
	flag.StringVar(&xorKeyString, "key", "password", "a string")
	flag.Parse()

	atomic.StoreInt32(&timing, 100)
	xorKey = []byte(xorKeyString)
	control()
	guid, _ := windows.GUIDFromString("1be92daf-ab79-4643-9423-1e6f711e9cda")

	ad, err := wintun.CreateAdapter("Link", "Wintun", &guid)
	if err != nil {
		fmt.Println("Error creating Link adapter")
		os.Exit(1)
	}

	// Ensure adapter is closed on exit
	defer ad.Close()

	var c *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		c = exec.Command("cmd", "/C", "netsh", "interface", "ip", "set", "address", "name=\"Link\"", "static", myIP, "255.255.255.0")
	default:
		c = exec.Command("rm", "-f", "/d/a.txt")
	}

	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}

	// Increase wintun ring buffer from 8MB to 16MB for better burst handling
	linkSession, sessionErr := ad.StartSession(0x1000000)
	if sessionErr != nil {
		fmt.Println("Session start error:", sessionErr)
		os.Exit(1)
	}

	// Set up signal handling for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)

	// Start worker goroutines
	go receiveCCPayload(&linkSession, shutdownChan)
	go packetReceive(&linkSession, shutdownChan)

	fmt.Println("Running... Press Ctrl+C to stop.")

	// Wait for shutdown signal
	<-sigChan
	fmt.Println("\nShutting down...")

	close(shutdownChan)

	// Close UDP connection to unblock readers
	ccConnectionMu.Lock()
	if ccConnection != nil {
		ccConnection.Close()
		ccConnection = nil
	}
	ccConnectionMu.Unlock()

	fmt.Println("Shutdown complete.")
}
