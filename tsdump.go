package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"log"
	"net"
	"strings"

	// golang x/net makes it a mess to do this dual stack
	"golang.org/x/net/ipv4"
)

var (
	ifaceFlag = flag.String("interface", "eth0", "Name of interface to work on")
	portFlag  = flag.String("port", "7050", "UDP port to work on")
	groupFlag = flag.String("groups", "239.24.0.1", "comma separated list  of multicast groups to work on")
	groups    = []string{}
)

func main() {
	flag.Parse()

	iface, err := net.InterfaceByName(*ifaceFlag)
	if err != nil {
		panic(err)
	}

	connection, err := net.ListenPacket("udp", ":"+*portFlag)
	if err != nil {
		panic(err)
	}
	defer connection.Close()

	groups = strings.Split(*groupFlag, ",")

	// 28 = 20 IPv4 + 8 UDP
	b := make([]byte, 1500)

	cc := make(map[string]map[uint64]uint64)

	var packetGroup string

	packetConn := ipv4.NewPacketConn(connection)
	if err := packetConn.SetControlMessage(ipv4.FlagDst, true); err != nil {
		panic(err)
	}

	for _, v := range groups {
		group := net.ParseIP(v)
		if !group.IsMulticast() {
			log.Println("not a valid multicast group")
		}
		if group.To4() == nil {
			log.Fatalf("IPv6 multicast not currently supported")
		}
		if err := packetConn.JoinGroup(iface, &net.UDPAddr{IP: group}); err != nil {
			panic(err)
		}

		//syncState[v].Set(1)

		cc[group.String()] = make(map[uint64]uint64)

		log.Println("Joined " + group.String())

		//time.Sleep(60 * time.Second)
	}

	for {
		//n, cm, src, err := p.ReadFrom(b)
		payloadLength, cm, _, err := packetConn.ReadFrom(b)
		if err != nil {
			panic(err)
		}

		// what group is this udp packet from
		packetGroup = cm.Dst.String()
		var packetType string

		if cc[packetGroup] == nil {
			log.Println("Packet from group we're not part of: " + packetGroup)
			continue
		}

		for mp2tHeader := 0; mp2tHeader <= 1138; mp2tHeader = mp2tHeader + 188 {
			// what CC has this packet
			c := uint64(b[mp2tHeader+3] & 0x0f)

			// what PID has this packet
			var bpid []byte
			bpid = append(bpid, 0, 0, 0, 0, 0, 0, b[mp2tHeader+1]&0b00011111, b[mp2tHeader+2])
			pid := binary.BigEndian.Uint64(bpid)
			switch pid {
			case 0x0000:
				packetType = "Program association table(PAT)"
			case 0x0001:
				packetType = "Conditional Access Table(CAT)"
			case 0x0002:
				packetType = "Transport stream description table(TSDT)"
			case 0x0003:
				packetType = "IPMP control information table"
			case 0x0010:
				packetType = "DVB: NIT/ST"
			case 0x0011:
				packetType = "DVB: Service description table(SDT)/BAT/ST"
			case 0x0012:
				packetType = "DVB: Event information table(EIT)/ST/CIT"
			case 0x0013:
				packetType = "DVB: RST/ST"
			case 0x0014:
				packetType = "DVB: TDT/Time offset table(TOT)/Stuffing table(ST)"
			case 0x0015:
				packetType = "DVB: network synchronization"
			case 0x1fff:
				// NIL
				continue
			default:
				packetType = fmt.Sprintf("Unknown, PID: %x", pid)

			}
			log.Printf("Packet(%db, cc%d): %s", payloadLength, c, packetType)
		}
	}
}
