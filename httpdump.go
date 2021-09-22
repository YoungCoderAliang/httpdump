package httpdump

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
)

type TcpChannel struct {
	srcIP   string
	dstIP   string
	srcPort layers.TCPPort
	dstPort layers.TCPPort
}

type TcpTask struct {
	ipv4 *layers.IPv4
	tcp  *layers.TCP
}

type HttpCache struct {
	httpStart time.Time

	reqSeqMap map[uint32]bool
	reqList   []TcpTask

	resSeqMap map[uint32]bool
	resList   []TcpTask
	resStart  bool
}

type HttpPacket struct {
	ch  TcpChannel
	req *http.Request
	res *http.Response
}

// support : simple network flow in http 1.0 / http 1.1
// not support : http 2 (ignore), https (ignore), Transfer-Encoding: chunked (response is replaced by text 'error')
func DumpIf(path string) chan HttpPacket {
	httpChan := make(chan HttpPacket, 10000)

	var ipv4Chans [256]chan TcpTask
	for i := 0; i < 256; i++ {
		ipv4Chans[i] = make(chan TcpTask, 10000)
		go httpPacketCollector(i, ipv4Chans[i], httpChan)
	}

	go func() {
		handler, err := pcap.OpenLive(path, 102400, false, 30)
		if err != nil {
			log.Fatalln(err)
			panic(errors.New("can't open live path : " + path))
		}

		source := gopacket.NewPacketSource(handler, handler.LinkType())
		defer handler.Close()
		i := 0
		for packet := range source.Packets() {
			i++
			layer := packet.Layer(layers.LayerTypeIPv4)
			if layer == nil {
				continue
			}
			ipv4 := layer.(*layers.IPv4)
			layer = packet.Layer(layers.LayerTypeTCP)
			if layer == nil {
				continue
			}
			tcp := layer.(*layers.TCP)
			rt := (ipv4.SrcIP[3] | ipv4.DstIP[3]) & 255
			ipv4Chans[rt] <- TcpTask{ipv4, tcp}
		}
	}()
	return httpChan
}

func ip2string(ip net.IP) string {
	var a, b, c, d = (int)(ip[0]), (int)(ip[1]), (int)(ip[2]), (int)(ip[3])
	return strings.Join([]string{strconv.Itoa(a), strconv.Itoa(b), strconv.Itoa(c), strconv.Itoa(d)}, ".")
}

func httpPacketCollector(id int, tasks chan TcpTask, httpChan chan HttpPacket) {
	comp := [4][]byte{[]byte("GET "), []byte("POST "), []byte("DELETE "), []byte("PUT ")}
	resComp := []byte("HTTP")
	tcpCache := make(map[TcpChannel]*HttpCache, 1024)
	for tcpTask := range tasks {
		srcIp, dstIp, srcPort, dstPort := ip2string(tcpTask.ipv4.SrcIP), ip2string(tcpTask.ipv4.DstIP), tcpTask.tcp.SrcPort, tcpTask.tcp.DstPort
		reqDirection := true
		ch := TcpChannel{srcIp, dstIp, srcPort, dstPort}
		httpCache, ok := tcpCache[ch]
		if !ok {
			reqDirection = false
			ch = TcpChannel{dstIp, srcIp, dstPort, srcPort}
			httpCache, ok = tcpCache[ch]
		}
		if ok && tcpTask.tcp.SYN {
			delete(tcpCache, ch)
			continue
		}
		if ok {
			if reqDirection {
				httpCache.reqList = addAndSortPacket(httpCache.reqSeqMap, httpCache.reqList, tcpTask)
			} else {
				if !httpCache.resStart {
					if len(tcpTask.tcp.Payload) > 10 && byteSameStart(resComp, tcpTask.tcp.Payload) {
						httpCache.resStart = true
					} else {
						continue
					}
				}
				httpCache.resList = addAndSortPacket(httpCache.resSeqMap, httpCache.resList, tcpTask)
				if httpEnd(httpCache) {
					fmt.Println("http ends ", ch)
					httpPacket := transferHttpPacket(httpCache, ch)
					if httpPacket != nil {
						httpChan <- *httpPacket
					}
					delete(tcpCache, ch)
				}
			}
			if ok && tcpTask.tcp.FIN {
				fmt.Println("fin detected :", ch)
				delete(tcpCache, ch)
				continue
			}
		} else {
			payload := tcpTask.tcp.Payload
			if len(payload) < 10 {
				continue
			}
			for _, cp := range comp {
				if byteSameStart(cp, payload) {
					httpCache = &HttpCache{
						reqSeqMap: make(map[uint32]bool, 16),
						resSeqMap: make(map[uint32]bool, 16),
						reqList:   []TcpTask{},
						resList:   []TcpTask{},
						httpStart: time.Now()}
					tcpCache[TcpChannel{srcIp, dstIp, srcPort, dstPort}] = httpCache
					httpCache.reqList = addAndSortPacket(httpCache.reqSeqMap, httpCache.reqList, tcpTask)
					break
				}
			}
		}
	}
}

func httpEnd(httpCache *HttpCache) bool {
	var LF byte = 0x0A
	var CR byte = 0x0D
	// CRLF := []byte{CR, LF}
	// var COLON byte = ':'
	// var TAB byte = 0x09
	// var SPACE byte = 0x20

	resBytes := merge(httpCache.resList)
	var headerEnd int = 0
	var lines []string = []string{}
	for id, bt := range resBytes {
		if id >= 3 && bt == LF && resBytes[id-1] == CR && resBytes[id-2] == LF && resBytes[id-3] == CR {
			headerEnd = id
			before := string(resBytes[:id-3])
			lines = strings.Split(before, "\r\n")
			break
		}
	}
	if headerEnd == 0 {
		return false
	}
	var contentLengh int = 0
	for _, line := range lines {
		if strings.HasPrefix(line, "Content-Length: ") {
			cl, e := strconv.Atoi(line[16:])
			if e == nil {
				contentLengh = cl
				break
			} else {
				fmt.Println("can't parse ", line)
				return true
			}
		}
	}
	if contentLengh == 0 {
		return true
	}
	return len(resBytes)-headerEnd-1 >= contentLengh
}

func addAndSortPacket(seqMap map[uint32]bool, packetList []TcpTask, tcpTask TcpTask) []TcpTask {
	_, ok := seqMap[tcpTask.tcp.Seq]
	if !ok {
		seqMap[tcpTask.tcp.Seq] = true
		packetList = append(packetList, tcpTask)
		sort.Slice(packetList, func(i, j int) bool {
			return packetList[i].tcp.Seq < packetList[j].tcp.Seq
		})
	}
	return packetList
}

func transferHttpPacket(httpCache *HttpCache, tcpChannel TcpChannel) *HttpPacket {
	reqBytes := merge(httpCache.reqList)
	resBytes := merge(httpCache.resList)
	req, e := http.ReadRequest(bufio.NewReader(bytes.NewReader(reqBytes)))
	if e != nil {
		fmt.Println("http.ReadRequest fail ", e)
		return nil
	}
	res, e := http.ReadResponse(bufio.NewReader(bytes.NewReader(resBytes)), req)
	if e != nil {
		fmt.Println("http.ReadResponse fail ", e)
		return nil
	}
	result := HttpPacket{tcpChannel, req, res}
	return &result
}

func merge(paks []TcpTask) []byte {
	reqBytes := []byte{}
	for _, req := range paks {
		reqBytes = append(reqBytes, req.tcp.Payload...)
	}
	return reqBytes
}

func byteSameStart(cp []byte, payload []byte) bool {
	eq := true
	for id, bt := range cp {
		if payload[id] != bt {
			eq = false
			break
		}
	}
	return eq
}
