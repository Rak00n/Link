package main

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"flag"
	"fmt"
	"math/big"

	//"github.com/Microsoft/go-winio/pkg/guid"
	"github.com/Rak00n/wintun-go"
	"net"
	"os"
	"os/exec"
	"runtime"
	"golang.org/x/sys/windows"
	"time"
)

var serverIpPort string
var clientID string
var timing int
var maxTiming int
var minTiming int

type ccPacket struct {
	PacketType string      `json:"packetType"`
	PacketPayload string `json:"payload"`
}

func xorBytes(data []byte, key[]byte) []byte {
	//return data
	c := make([]byte, len(data))
	for i := range data {
		c[i] = data[i] ^ key[i%len(key)]
	}
	return c
}


func packetReceive(session *wintun.Session) {
	//winHandle := session.wintun ReadWaitEvent()



	for {
		packetReceived,err := session.ReceivePacket()
		if len(packetReceived) == 0 {
			if timing < maxTiming {
				timing = timing + 100
			}
			time.Sleep(time.Duration(timing) * time.Microsecond)
		} else {
			if err == nil {
				timing = minTiming
				fmt.Println(packetReceived, err)
				//if packetReceived[0] != 96 && packetReceived[0] != 69 {
				if packetReceived[0] != 1 {
					fmt.Println(packetReceived[0])
					fmt.Println(packetReceived, err)
					h := fmt.Sprintf("%016x",packetReceived)
					fmt.Println(h)
					sendCCPayload("networkPacket",packetReceived)
				}

				session.ReleaseReceivePacket(packetReceived)
			}
		}

		//fmt.Println(err)

	}
}

func packetSend(session *wintun.Session, packet []byte) {

	fmt.Println(len(packet))
		pk, err := session.AllocateSendPacket(len(packet))
		fmt.Println(err)
		copy(pk, packet)
		session.SendPacket(pk)
		//time.Sleep(1*time.Second)
	}
func control() {
	serverAddress, _ := net.ResolveUDPAddr("udp", serverIpPort)
	ccConnection, _ = net.DialUDP("udp", nil, serverAddress)
	fmt.Println("UDP connected",ccConnection)
	//return conn
}

func int2ip(nn uint32) net.IP {
	ip := make(net.IP, 4)
	binary.BigEndian.PutUint32(ip, nn)
	return ip
}

var ccConnection *net.UDPConn
var xorKey []byte

func sendCCPayload(packetType string,packet []byte) {
	//c := make([]byte, len(packet))
	//for i := range packet {
	//	c[i] = packet[i] ^ xorKey[i%len(xorKey)]
	//}
	ip := []byte{packet[16],packet[17],packet[18],packet[19]}
	v := int(big.NewInt(0).SetBytes(ip).Uint64())
	dstIP := int2ip(uint32(v))
	sEnc := base64.StdEncoding.EncodeToString(xorBytes(packet,xorKey))

	body := []byte(`{
		"networkID": 1,
		"clientID": `+clientID+`,
		"srcIp": "`+myIP+`",
		"packetType": "`+packetType+`",
		"dstIP": "`+dstIP.String()+`",
		"payload": "`+sEnc+`"}`)
	fmt.Fprintf(ccConnection, string(body))
}

func receiveCCPayload(session *wintun.Session) {
	for {

		p :=  make([]byte, 65535)
		
		fmt.Println("Waiting for payload from server",ccConnection)
		n,remoteaddr,err := ccConnection.ReadFromUDP(p)
		p = bytes.Trim(p, "\x00")
		fmt.Println(n)
		fmt.Println(remoteaddr)
		fmt.Println(p)
		fmt.Println(err)
		fmt.Println("Got CC Packet")
		pString := string(p)
		fmt.Println(pString)
		data := ccPacket{}
		err = json.Unmarshal(p, &data)
		fmt.Println(data, err)
		if data.PacketType == "networkPacket" {
			timing = minTiming
			pBytes,_ := base64.StdEncoding.DecodeString(data.PacketPayload)
			pBytes = xorBytes(pBytes,xorKey)
			fmt.Println(pBytes)
			h := fmt.Sprintf("%016x",pBytes)
			fmt.Println(h)
			//go packetSend(linkSession,packet)
			packetSend(session,pBytes)
		} else if data.PacketType == "controlMessage" {
			pBytes,_ := base64.StdEncoding.DecodeString(data.PacketPayload)
			fmt.Println("Control Message", string(pBytes))
			//var c *exec.Cmd
			//
			//switch runtime.GOOS{
			//case "windows":
			//	c = exec.Command("cmd", "/C", "netsh", "interface", "ip", "set", "address", "name=\"link\"", "static", "10.10.10.110", "255.255.255.0")
			//
			//default://Mac & Linux
			//	//c = exec.Command("rm", "-f", "/d/a.txt")
			//}

			//if err := c.Run(); err != nil {
			//	fmt.Println("Error: ", err)
			//}
		}

	}

}

func cc() {
	for {
		//sendCCPayload("controlMessage",[]byte("hello"))
		time.Sleep(1*time.Second)
	}
}

var myIP string
var xorKeyString string
func main() {
	//token := windows.Token(0)
	//fmt.Println(token)
	flag.StringVar(&myIP,"myIP", "127.0.0.1", "a string")
	flag.StringVar(&clientID,"clientID", "1", "a string")
	flag.StringVar(&serverIpPort,"serverIpPort", "127.0.0.1:8082", "a string")
	flag.StringVar(&xorKeyString,"key", "password", "a string")
	flag.Parse()

	timing = 100
	maxTiming = 1000
	minTiming = 0
	//serverIpPort = "178.208.85.132:8082"
	//serverIpPort = "127.0.0.1:8082"
	xorKey = []byte(xorKeyString)
	control()
	guid,_ := windows.GUIDFromString("1be92daf-ab79-4643-9423-1e6f711e9cda")

	ad,err := wintun.CreateAdapter("Link","Wintun",&guid)
	if err != nil {
		fmt.Println("Error creating Link adapter")
		os.Exit(1)
	}
	var c *exec.Cmd

	switch runtime.GOOS{
	case "windows":
		c = exec.Command("cmd", "/C", "netsh", "interface", "ip", "set", "address", "name=\"Link\"", "static", myIP, "255.255.255.0")

	default://Mac & Linux
		c = exec.Command("rm", "-f", "/d/a.txt")
	}

	if err := c.Run(); err != nil {
		fmt.Println("Error: ", err)
	}
	linkSession,sessionErr := ad.StartSession(0x800000)
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
	time.Sleep(3000*time.Second)
	ad.Close()
}
