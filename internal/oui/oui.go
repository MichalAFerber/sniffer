// Package oui maps MAC prefixes to vendor names. The table is a short
// built-in list; pass a IEEE oui.csv with LoadFile for a full lookup.
package oui

import (
	"bufio"
	"os"
	"strings"
	"sync"
)

var (
	mu    sync.RWMutex
	table = map[string]string{
		"000c29": "VMware",
		"00155d": "Microsoft Hyper-V",
		"001a11": "Google",
		"001b63": "Apple",
		"001e06": "Wistron",
		"001f3b": "Intel",
		"00259d": "Motorola",
		"0050f2": "Microsoft",
		"00d0b7": "Intel",
		"041e64": "Apple",
		"08ecf5": "Cisco",
		"0c8bfd": "Intel",
		"107b44": "ASUS",
		"18b430": "Nest",
		"1c69a5": "BlackBerry",
		"247703": "Intel",
		"28d244": "TP-Link",
		"2c54cf": "LG",
		"3c5ab4": "Google",
		"3cecef": "Super Micro",
		"48d6d5": "Google",
		"4c3275": "Apple",
		"50ed3c": "Raspberry Pi",
		"54af97": "Amazon",
		"5cf370": "CC&C",
		"60f189": "Roku",
		"640bd7": "Apple",
		"6c4008": "Apple",
		"707d95": "Raspberry Pi",
		"78e103": "Amazon",
		"7c67a2": "Intel",
		"88e9fe": "Apple",
		"8c8590": "Apple",
		"94e979": "Liteon",
		"a4c138": "Telink",
		"acbc32": "Apple",
		"b827eb": "Raspberry Pi",
		"bcff4d": "Espressif",
		"c83a35": "Tenda",
		"d05099": "Raspberry Pi",
		"d83add": "Raspberry Pi",
		"dca632": "Raspberry Pi",
		"dc4427": "TP-Link",
		"e45f01": "Raspberry Pi",
		"e8ea6a": "Raspberry Pi",
		"f0d4e2": "Dell",
		"f4f5d8": "Google",
		"fc1596": "Espressif",
	}
)

func Lookup(mac string) string {
	p := prefix(mac)
	if p == "" {
		return ""
	}
	mu.RLock()
	defer mu.RUnlock()
	return table[p]
}

func prefix(mac string) string {
	var hex [6]byte
	n := 0
	for i := 0; i < len(mac) && n < 6; i++ {
		c := mac[i]
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			continue
		}
		hex[n] = v
		n++
	}
	if n < 6 {
		return ""
	}
	const h = "0123456789abcdef"
	return string([]byte{
		h[hex[0]], h[hex[1]],
		h[hex[2]], h[hex[3]],
		h[hex[4]], h[hex[5]],
	})
}

// LoadFile reads an IEEE-style "hex,vendor" or "hex\tvendor" file.
func LoadFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	next := map[string]string{}
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		var hex, name string
		if i := strings.IndexByte(line, ','); i > 0 {
			hex, name = line[:i], line[i+1:]
		} else if i := strings.IndexByte(line, '\t'); i > 0 {
			hex, name = line[:i], line[i+1:]
		} else {
			continue
		}
		p := prefix(hex)
		name = strings.TrimSpace(name)
		if p == "" || name == "" {
			continue
		}
		next[p] = name
	}
	if err := sc.Err(); err != nil {
		return err
	}
	mu.Lock()
	for k, v := range next {
		table[k] = v
	}
	mu.Unlock()
	return nil
}
