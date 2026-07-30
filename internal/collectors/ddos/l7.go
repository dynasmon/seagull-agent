package ddos

import "bytes"

func isHTTPPort(port int) bool {
	switch port {
	case 80, 8080, 8000, 8888, 5000, 3000:
		return true
	default:
		return false
	}
}

func isTLSPort(port int) bool {
	switch port {
	case 443, 8443, 9443, 10443:
		return true
	default:
		return false
	}
}

func isHTTPPayload(payload []byte) bool {
	if len(payload) < 4 {
		return false
	}
	p := bytes.TrimLeft(payload, "\r\n\t ")
	if len(p) < 4 {
		return false
	}
	if bytes.HasPrefix(p, []byte("GET ")) ||
		bytes.HasPrefix(p, []byte("POST ")) ||
		bytes.HasPrefix(p, []byte("HEAD ")) ||
		bytes.HasPrefix(p, []byte("PUT ")) ||
		bytes.HasPrefix(p, []byte("DELETE ")) ||
		bytes.HasPrefix(p, []byte("OPTIONS ")) ||
		bytes.HasPrefix(p, []byte("PATCH ")) {
		return true
	}
	if bytes.HasPrefix(p, []byte("PRI * HTTP/2.0")) {
		return true
	}
	return false
}

func isTLSClientHello(payload []byte) bool {
	if len(payload) < 6 {
		return false
	}
	if payload[0] != 0x16 {
		return false
	}
	if payload[1] != 0x03 {
		return false
	}
	if payload[2] < 0x01 || payload[2] > 0x04 {
		return false
	}
	if payload[5] != 0x01 {
		return false
	}
	return true
}
