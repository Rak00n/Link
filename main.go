package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"golang.zx2c4.com/wintun"
	"golang.org/x/sys/windows"
)

var serverIpPort string
var clientID string
var timing atomic.Int64
var maxTiming int64 = 1000
var minTiming int64 = 0

type ccPacket struct {
	PacketType    string `json:"packetType"`
	PacketPayload string `json:"payload"`
}

func xorBytes(data []byte, key []byte) []byte {
	//return data
	c := make([]byte, len(data))
	for i := range data {
		c[i] = data[i] ^ key[i%len(key)]
	}
	return c
}

func packetReceive(session *wintun.Session) {
	// Use wintun's ReadWaitEvent for blocking wait instead of busy-looping
	// This eliminates CPU waste when no packets are available
	for {
		packetReceived, err := session.ReceivePacket()
		if len(packetReceived) == 0 {
			// No packet available — increase backoff delay using atomic access
			current := timing.Load()
			if current < maxTiming {
				timing.Add(100)
			}
			time.Sleep(time.Duration(timing.Load()) * time.Microsecond)
		} else {
			if err == nil {
				// Reset timing on successful receive
				timing.Store(minTiming)

				// Skip non-network packets (type != 1) silently
				if packetReceived[0] != 1 {
					sendCCPayload("networkPacket", packetReceived)
				}
			}
			session.ReleaseReceivePacket(packetReceived)
		}
	}
}

func packetSend(session *wintun.Session, packet []byte) {
	pk, err := session.AllocateSendPacket(len(packet))
	if err != nil {
		return
	}
	copy(pk, packet)
	session.SendPacket(pk)
}
func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

var ccConnection *net.UDPConn
var ccConnectionMu sync.Mutex
var xorKey []byte

// reconnectCC safely reconnects the UDP connection with mutex protection
func reconnectCC() {
	ccConnectionMu.Lock()
	defer ccConnectionMu.Unlock()

	if ccConnection != nil {
		ccConnection.Close()
	}

	serverAddress, err := net.ResolveUDPAddr("udp", serverIpPort)
	if err != nil {
		return
	}

	conn, err := net.DialUDP("udp", nil, serverAddress)
	if err != nil {
		return
	}
	ccConnection = conn
}

func control() {
	reconnectCC()
	fmt.Println("UDP connected")
	//return conn
}

type ccOutgoingPacket struct {
	NetworkID     int    `json:"networkID"`
	ClientID      string `json:"clientID"`
	SrcIP         string `json:"srcIp"`
	PacketType    string `json:"packetType"`
	DstIP         string `json:"dstIP"`
	PacketPayload string `json:"payload"`
}

func sendCCPayload(packetType string, packet []byte) {
	ip := []byte{packet[16], packet[17], packet[18], packet[19]}
	v := int(big.NewInt(0).SetBytes(ip).Uint64())
	dstIP := int2ip(uint32(v))
	sEnc := base64.StdEncoding.EncodeToString(xorBytes(packet, xorKey))

	body := ccOutgoingPacket{
		NetworkID:     1,
		ClientID:      clientID,
		SrcIP:         myIP,
		PacketType:    packetType,
		DstIP:         dstIP.String(),
		PacketPayload: sEnc,
	}

	jsonBytes, err := json.Marshal(body)
	if err != nil {
		return
	}

	ccConnectionMu.Lock()
	_, err = ccConnection.Write(jsonBytes)
	ccConnectionMu.Unlock()

	if err != nil {
		reconnectCC()
	}
}

func receiveCCPayload(session *wintun.Session) {
	// Reuse buffer to avoid repeated allocations
	p := make([]byte, 65535)
	ccPacketBuf := ccPacket{}

	for {
		ccConnectionMu.Lock()
		conn := ccConnection
		ccConnectionMu.Unlock()

		if conn == nil {
			time.Sleep(100 * time.Millisecond)
			continue
		}

		// Set read deadline for timeout handling
		conn.SetReadDeadline(time.Now().Add(5 * time.Second))

		n, _, err := conn.ReadFromUDP(p)
		if err != nil {
			// Check if the error is a timeout — if so, reconnect
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				reconnectCC()
				continue
			}
			// Other errors: attempt reconnection
			reconnectCC()
			continue
		}

		// Trim null bytes from buffer
		p = bytes.Trim(p[:n], "\x00")

		// Reset read deadline after successful read
		conn.SetReadDeadline(time.Time{})

		// Reset timing on successful receive
		timing.Store(minTiming)

		// Unmarshal JSON into reusable buffer
		if err := json.Unmarshal(p, &ccPacketBuf); err != nil {
			continue
		}

		if ccPacketBuf.PacketType == "networkPacket" {
			pBytes, err := base64.StdEncoding.DecodeString(ccPacketBuf.PacketPayload)
			if err != nil {
				continue
			}
			pBytes = xorBytes(pBytes, xorKey)
			packetSend(session, pBytes)
		} else if ccPacketBuf.PacketType == "controlMessage" {
			pBytes, err := base64.StdEncoding.DecodeString(ccPacketBuf.PacketPayload)
			if err != nil {
				continue
			}
			_ = pBytes // control message handling can be added here
		}

		// Reset buffer for next read
		p = make([]byte, 65535)
	}
}

func cc() {
	for {
		time.Sleep(30 * time.Second)
		// Periodic health check: try to send a keepalive
		ccConnectionMu.Lock()
		conn := ccConnection
		ccConnectionMu.Unlock()

		if conn == nil {
			continue
		}

		conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
		_, err := conn.Write([]byte("{}"))
		if err != nil {
			reconnectCC()
		}
		conn.SetWriteDeadline(time.Time{})
	}
}

var myIP string
var xorKeyString string

func main() {
	//token := windows.Token(0)
	//fmt.Println(token)
	flag.StringVar(&myIP, "myIP", "127.0.0.1", "a string")
	flag.StringVar(&clientID, "clientID", "1", "a string")
	flag.StringVar(&serverIpPort, "serverIpPort", "127.0.0.1:8082", "a string")
	flag.StringVar(&xorKeyString, "key", "password", "a string")
	flag.Parse()

	timing.Store(100)
	//serverIpPort = "178.208.85.132:8082"
	//serverIpPort = "127.0.0.1:8082"
	xorKey = []byte(xorKeyString)
	control()
	guid, _ := windows.GUIDFromString("1be92daf-ab79-4643-9423-1e6f711e9cda")

	ad, err := wintun.CreateAdapter("Link", "Wintun", &guid)
	if err != nil {
		fmt.Println("Error creating Link adapter")
		os.Exit(1)
	}
	var c *exec.Cmd

	switch runtime.GOOS {
	case "windows":
		c = exec.Command("cmd", "/C", "netsh", "interface", "ip", "set", "address", "name=\"Link\"", "static", myIP, "255.255.255.0")

	default: //Mac & Linux
		c = exec.Command("rm", "-f", "/d/a.txt")
	}

	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}
	linkSession, sessionErr := ad.StartSession(0x800000)
	linkSession.ReadWaitEvent()
	fmt.Println(ad)
	//ad.LUID()
	//winipcfg.GetAdaptersAddresses()
	fmt.Println(err)
	fmt.Println(linkSession)
	fmt.Println(sessionErr)
	go cc()
	go receiveCCPayload(&linkSession)
	go packetReceive(&linkSession)
	//packet := []byte{69,0,0,52,49,192,64,0,128,6,181,1,10,0,0,1,10,0,0,2,253,71,0,80,52,77,170,169,0,0,0,0,128,2,255,255,132,91,0,0,2,4,255,215,1,3,3,8,1,1,4,2}
	//h := fmt.Sprintf("%016x",packet)
	//fmt.Println(h)
	//go packetSend(linkSession,packet)
	time.Sleep(3000 * time.Second)
	ad.Close()
}
