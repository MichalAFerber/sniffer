package decode

import (
	"encoding/binary"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

func TestARPReply(t *testing.T) {
	frame := make([]byte, 42)
	copy(frame[0:6], []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff})
	copy(frame[6:12], []byte{0xb8, 0x27, 0xeb, 0x00, 0x00, 0x01})
	frame[12], frame[13] = 0x08, 0x06
	arp := frame[14:]
	binary.BigEndian.PutUint16(arp[0:2], 1)
	binary.BigEndian.PutUint16(arp[2:4], 0x0800)
	arp[4], arp[5] = 6, 4
	binary.BigEndian.PutUint16(arp[6:8], 2)
	copy(arp[8:14], []byte{0xb8, 0x27, 0xeb, 0x00, 0x00, 0x01})
	copy(arp[14:18], []byte{192, 168, 1, 50})
	copy(arp[24:28], []byte{192, 168, 1, 1})

	got := Frame(frame)
	if len(got) != 1 {
		t.Fatalf("got %d obs", len(got))
	}
	o := got[0]
	if o.Kind != obs.KindARP {
		t.Fatalf("kind %s", o.Kind)
	}
	if o.SrcIP != "192.168.1.50" || o.ExtraGet("op") != "reply" {
		t.Fatalf("%+v extra=%v", o, o.Extra)
	}
	if o.ExtraGet("sha") != "b8:27:eb:00:00:01" {
		t.Fatalf("sha %s", o.ExtraGet("sha"))
	}
}

func TestDNSQuery(t *testing.T) {
	q := EncodeQuery(0x1234, "example.com", 1)
	frame := fakeUDP(q, 55555, 53)
	got := Frame(frame)
	if len(got) == 0 {
		t.Fatal("no observations")
	}
	found := false
	for _, o := range got {
		if o.Kind == obs.KindDNS && o.Hostname == "example.com" && o.ExtraGet("qtype") == "A" {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing DNS qname: %+v", got)
	}
}

func TestDNSPTRCompression(t *testing.T) {
	// Hand-built response: qname example.com A, answer example.com A 93.184.216.34
	// with pointer compression on the answer name.
	msg := EncodeQuery(0x1, "example.com", 1)
	// qdcount already 1; bump ancount
	binary.BigEndian.PutUint16(msg[6:8], 1)
	// answer: pointer to offset 12 (the question name)
	ans := []byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 93, 184, 216, 34}
	msg = append(msg, ans...)
	got := Frame(fakeUDP(msg, 53, 55555))
	found := false
	for _, o := range got {
		if o.ExtraGet("answer") == "93.184.216.34" && o.ExtraGet("qname") == "example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("compressed PTR/A not parsed: %+v", dump(got))
	}
}

func TestHTTPHost(t *testing.T) {
	req := []byte("GET / HTTP/1.1\r\nHost: printer.lan:80\r\nUser-Agent: curl\r\n\r\n")
	frame := fakeTCP(req, 54321, 80, 0x18)
	got := Frame(frame)
	found := false
	for _, o := range got {
		if o.Kind == obs.KindHTTP && o.Hostname == "printer.lan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("host not parsed: %+v", dump(got))
	}
}

func TestTLSSNI(t *testing.T) {
	hello := clientHello("www.example.com")
	frame := fakeTCP(hello, 40000, 443, 0x18)
	got := Frame(frame)
	found := false
	for _, o := range got {
		if o.Kind == obs.KindTLS && o.Hostname == "www.example.com" {
			found = true
		}
	}
	if !found {
		t.Fatalf("sni not parsed: %+v", dump(got))
	}
}

func TestSSDP(t *testing.T) {
	body := []byte("NOTIFY * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nLOCATION: http://192.168.1.20:8080/desc.xml\r\nSERVER: Linux/3.0 UPnP/1.0\r\nNT: upnp:rootdevice\r\n\r\n")
	got := Frame(fakeUDP(body, 1900, 1900))
	found := false
	for _, o := range got {
		if o.Kind == obs.KindSSDP && o.Hostname == "192.168.1.20" && strings.Contains(o.ExtraGet("server"), "UPnP") {
			found = true
		}
	}
	if !found {
		t.Fatalf("ssdp: %+v", dump(got))
	}
}

func TestDHCPHostname(t *testing.T) {
	b := make([]byte, 300)
	b[0] = 1 // boot request
	b[1], b[2], b[3] = 1, 6, 0
	copy(b[28:34], []byte{0xdc, 0xa6, 0x32, 0x01, 0x02, 0x03})
	binary.BigEndian.PutUint32(b[236:240], 0x63825363)
	opt := b[240:]
	opt[0], opt[1], opt[2] = 53, 1, 1 // discover
	opt[3], opt[4] = 12, 7
	copy(opt[5:12], []byte("pizero2"))
	opt[12] = 255
	got := Frame(fakeUDP(b, 68, 67))
	if len(got) != 1 || got[0].Kind != obs.KindDHCP {
		t.Fatalf("dhcp: %+v", dump(got))
	}
	if got[0].Hostname != "pizero2" {
		t.Fatalf("hostname %q extra=%v", got[0].Hostname, got[0].Extra)
	}
	if got[0].ExtraGet("chaddr") != "dc:a6:32:01:02:03" {
		t.Fatalf("chaddr %s", got[0].ExtraGet("chaddr"))
	}
}

func TestShortFrame(t *testing.T) {
	if Frame([]byte{1, 2, 3}) != nil {
		t.Fatal("expected nil")
	}
}

func TestVLANIPv4(t *testing.T) {
	inner := fakeUDP(EncodeQuery(1, "a.local", 1), 5353, 5353)
	// insert 802.1Q after ethernet addrs
	vlan := make([]byte, 0, len(inner)+4)
	vlan = append(vlan, inner[:12]...)
	vlan = append(vlan, 0x81, 0x00, 0x00, 0x01)
	vlan = append(vlan, inner[12:]...)
	got := Frame(vlan)
	found := false
	for _, o := range got {
		if o.Kind == obs.KindMDNS && o.Hostname == "a.local" {
			found = true
		}
	}
	if !found {
		t.Fatalf("vlan mdns: %+v", dump(got))
	}
}

func fakeUDP(payload []byte, src, dst uint16) []byte {
	eth := make([]byte, 14+20+8+len(payload))
	copy(eth[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	eth[12], eth[13] = 0x08, 0x00
	ip := eth[14:]
	ip[0] = 0x45
	total := 20 + 8 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64
	ip[9] = 17
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{192, 168, 1, 1})
	u := ip[20:]
	binary.BigEndian.PutUint16(u[0:2], src)
	binary.BigEndian.PutUint16(u[2:4], dst)
	binary.BigEndian.PutUint16(u[4:6], uint16(8+len(payload)))
	copy(u[8:], payload)
	return eth
}

func fakeTCP(payload []byte, src, dst uint16, flags byte) []byte {
	eth := make([]byte, 14+20+20+len(payload))
	copy(eth[6:12], []byte{0x00, 0x11, 0x22, 0x33, 0x44, 0x55})
	eth[12], eth[13] = 0x08, 0x00
	ip := eth[14:]
	ip[0] = 0x45
	total := 20 + 20 + len(payload)
	binary.BigEndian.PutUint16(ip[2:4], uint16(total))
	ip[8] = 64
	ip[9] = 6
	copy(ip[12:16], []byte{192, 168, 1, 10})
	copy(ip[16:20], []byte{192, 168, 1, 1})
	th := ip[20:]
	binary.BigEndian.PutUint16(th[0:2], src)
	binary.BigEndian.PutUint16(th[2:4], dst)
	th[12] = 5 << 4
	th[13] = flags
	copy(th[20:], payload)
	return eth
}

func clientHello(sni string) []byte {
	// handshake body after type+len
	var body []byte
	body = append(body, 0x03, 0x03) // client version TLS 1.2
	body = append(body, make([]byte, 32)...)
	body = append(body, 0)          // session id len
	body = append(body, 0x00, 0x02) // cipher suites len
	body = append(body, 0x00, 0x2f)
	body = append(body, 0x01, 0x00) // compression
	// extensions
	name := []byte(sni)
	sniList := []byte{0x00} // hostname type
	var nl [2]byte
	binary.BigEndian.PutUint16(nl[:], uint16(len(name)))
	sniList = append(sniList, nl[:]...)
	sniList = append(sniList, name...)
	var listLen [2]byte
	binary.BigEndian.PutUint16(listLen[:], uint16(len(sniList)))
	sniData := append(listLen[:], sniList...)
	ext := []byte{0x00, 0x00} // SNI type
	var el [2]byte
	binary.BigEndian.PutUint16(el[:], uint16(len(sniData)))
	ext = append(ext, el[:]...)
	ext = append(ext, sniData...)
	var extLen [2]byte
	binary.BigEndian.PutUint16(extLen[:], uint16(len(ext)))
	body = append(body, extLen[:]...)
	body = append(body, ext...)

	hs := []byte{0x01, 0, 0, 0} // type + 3-byte len
	binary.BigEndian.PutUint32(hs[0:4], uint32(len(body)))
	hs[0] = 0x01
	hs = append(hs, body...)

	rec := []byte{0x16, 0x03, 0x01, 0, 0}
	binary.BigEndian.PutUint16(rec[3:5], uint16(len(hs)))
	return append(rec, hs...)
}

func dump(list []obs.Observation) string {
	var b strings.Builder
	for _, o := range list {
		b.WriteString(string(o.Kind) + " host=" + o.Hostname + " extra=")
		for k, v := range o.Extra {
			b.WriteString(k + "=" + v + " ")
		}
		b.WriteByte(';')
	}
	if b.Len() == 0 {
		return hex.EncodeToString(nil)
	}
	return b.String()
}
