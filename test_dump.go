package httpdump

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/google/gopacket/pcap"
)

func TestDump(t *testing.T) {
	start := time.Now()

	ifs, _ := pcap.FindAllDevs()
	for id, it := range ifs {
		fmt.Println(id, it.Name, it.Addresses)
	}
	fmt.Println("please input the number of interface to listen : ")

	in := bufio.NewReader(os.Stdin)
	bt, _, _ := in.ReadLine()
	id, _ := strconv.Atoi(string(bt))
	fmt.Println("running ...   interface id", id, "name :", ifs[id].Name)
	httpChan := DumpIf(ifs[id].Name)

	times := 0
	for httpPak := range httpChan {
		fmt.Println("\n ============ ")
		fmt.Println(times, time.Now())
		times++

		fmt.Printf("\n%s:%d -> %s:%d", httpPak.ch.srcIP, httpPak.ch.srcPort, httpPak.ch.dstIP, httpPak.ch.dstPort)
		fmt.Printf("\nrequest :\n%s http://%s%s\n", httpPak.req.Method, httpPak.req.Host, httpPak.req.URL)
		fmt.Println("\nrequest header :")
		for k, v := range httpPak.req.Header {
			fmt.Println(k, ":", v)
		}
		fmt.Println("\nrequest body :\n", reader2String(httpPak.req.Body))
		fmt.Println("\nresponse header :")
		for k, v := range httpPak.res.Header {
			fmt.Println(k, ":", v)
		}
		fmt.Println("\nresponse body :\n", reader2String(httpPak.res.Body))
		fmt.Println("\n ************ ")
	}
	fmt.Println(time.Since(start))
}

func reader2String(r io.Reader) string {
	buf := new(strings.Builder)
	_, err := io.Copy(buf, r)
	if err != nil {
		fmt.Println(err)
		return "error"
	}
	return buf.String()
}
