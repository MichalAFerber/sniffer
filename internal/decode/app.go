package decode

import (
	"bytes"
	"encoding/binary"
	"strings"

	"github.com/MichalAFerber/sniffer/internal/obs"
)

// tlsSNI extracts the server_name from a TLS ClientHello if present.
func tlsSNI(b []byte) string {
	// TLS record: type(1) ver(2) len(2)
	if len(b) < 5 || b[0] != 0x16 {
		return ""
	}
	recLen := int(binary.BigEndian.Uint16(b[3:5]))
	p := b[5:]
	if recLen > 0 && recLen < len(p) {
		p = p[:recLen]
	}
	// Handshake: type(1) len(3) — ClientHello = 1
	if len(p) < 4 || p[0] != 0x01 {
		return ""
	}
	hsLen := int(p[1])<<16 | int(p[2])<<8 | int(p[3])
	p = p[4:]
	if hsLen > 0 && hsLen < len(p) {
		p = p[:hsLen]
	}
	// client_version(2) + random(32)
	if len(p) < 34 {
		return ""
	}
	p = p[34:]
	if len(p) < 1 {
		return ""
	}
	sidLen := int(p[0])
	p = p[1:]
	if sidLen > len(p) {
		return ""
	}
	p = p[sidLen:]
	if len(p) < 2 {
		return ""
	}
	csLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if csLen > len(p) {
		return ""
	}
	p = p[csLen:]
	if len(p) < 1 {
		return ""
	}
	compLen := int(p[0])
	p = p[1:]
	if compLen > len(p) {
		return ""
	}
	p = p[compLen:]
	if len(p) < 2 {
		return ""
	}
	extLen := int(binary.BigEndian.Uint16(p[0:2]))
	p = p[2:]
	if extLen > len(p) {
		extLen = len(p)
	}
	exts := p[:extLen]
	for len(exts) >= 4 {
		typ := binary.BigEndian.Uint16(exts[0:2])
		n := int(binary.BigEndian.Uint16(exts[2:4]))
		exts = exts[4:]
		if n > len(exts) {
			return ""
		}
		data := exts[:n]
		exts = exts[n:]
		if typ != 0 {
			continue
		}
		// SNI: list_len(2) [type(1) name_len(2) name]
		if len(data) < 5 {
			return ""
		}
		data = data[2:]
		if data[0] != 0 {
			continue
		}
		nl := int(binary.BigEndian.Uint16(data[1:3]))
		data = data[3:]
		if nl > len(data) || nl == 0 {
			return ""
		}
		return sanitizeHost(string(data[:nl]))
	}
	return ""
}

func httpHost(b []byte) string {
	// Only look at the first line-block of a request.
	if len(b) < 8 {
		return ""
	}
	if !(bytes.HasPrefix(b, []byte("GET ")) ||
		bytes.HasPrefix(b, []byte("POST ")) ||
		bytes.HasPrefix(b, []byte("HEAD ")) ||
		bytes.HasPrefix(b, []byte("PUT ")) ||
		bytes.HasPrefix(b, []byte("PATCH ")) ||
		bytes.HasPrefix(b, []byte("DELETE ")) ||
		bytes.HasPrefix(b, []byte("OPTIONS "))) {
		return ""
	}
	// Cap parse window.
	if len(b) > 2048 {
		b = b[:2048]
	}
	end := bytes.Index(b, []byte("\r\n\r\n"))
	if end < 0 {
		end = len(b)
	}
	head := b[:end]
	for _, line := range bytes.Split(head, []byte("\r\n")) {
		lower := bytes.ToLower(line)
		if !bytes.HasPrefix(lower, []byte("host:")) {
			continue
		}
		v := strings.TrimSpace(string(line[5:]))
		if i := strings.IndexByte(v, ':'); i > 0 {
			v = v[:i]
		}
		return sanitizeHost(v)
	}
	return ""
}

func ssdp(base obs.Observation, b []byte) []obs.Observation {
	if len(b) < 8 {
		return []obs.Observation{base}
	}
	if !(bytes.HasPrefix(b, []byte("NOTIFY ")) ||
		bytes.HasPrefix(b, []byte("M-SEARCH ")) ||
		bytes.HasPrefix(bytes.ToUpper(b[:min(16, len(b))]), []byte("HTTP/"))) {
		return []obs.Observation{base}
	}
	if len(b) > 2048 {
		b = b[:2048]
	}
	o := base
	o.Kind = obs.KindSSDP
	for _, line := range bytes.Split(b, []byte("\r\n")) {
		if len(line) == 0 {
			break
		}
		colon := bytes.IndexByte(line, ':')
		if colon < 1 {
			continue
		}
		key := strings.ToLower(string(bytes.TrimSpace(line[:colon])))
		val := strings.TrimSpace(string(line[colon+1:]))
		switch key {
		case "server":
			o.ExtraSet("server", val)
		case "nt", "st":
			o.ExtraSet("nt", val)
		case "location":
			o.ExtraSet("location", val)
			if host := hostFromURL(val); host != "" {
				o.Hostname = host
			}
		case "usn":
			o.ExtraSet("usn", val)
		}
	}
	return []obs.Observation{o}
}

func hostFromURL(u string) string {
	// http://192.168.1.5:8080/desc.xml or http://name.local/…
	rest := u
	if i := strings.Index(rest, "://"); i >= 0 {
		rest = rest[i+3:]
	}
	if i := strings.IndexAny(rest, "/"); i >= 0 {
		rest = rest[:i]
	}
	if i := strings.IndexByte(rest, ']'); i >= 0 && strings.HasPrefix(rest, "[") {
		return rest[1:i]
	}
	if i := strings.LastIndexByte(rest, ':'); i > 0 {
		rest = rest[:i]
	}
	return sanitizeHost(rest)
}
