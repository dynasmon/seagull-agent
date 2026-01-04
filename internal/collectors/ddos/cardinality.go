package ddos

import (
	"math"
	"math/bits"
)

type cardCounter interface {
	Add(ip string)
	Estimate() int
	Kind() string
	Capped() bool
	Reset()
}

func newCardCounter(mode string, maxUnique, hllPrecision, bloomBits int) cardCounter {
	switch mode {
	case "hll":
		return newHLLCounter(maxUnique, hllPrecision)
	case "bloom":
		return newBloomCounter(maxUnique, bloomBits)
	case "map":
		return newMapCounter(maxUnique)
	default:
		return newHLLCounter(maxUnique, hllPrecision)
	}
}

func hash64String(s string) uint64 {
	const offset uint64 = 14695981039346656037
	const prime uint64 = 1099511628211
	h := offset
	for i := 0; i < len(s); i++ {
		h ^= uint64(s[i])
		h *= prime
	}
	return h
}

type mapCounter struct {
	max    int
	seen   map[string]struct{}
	capped bool
}

func newMapCounter(max int) *mapCounter {
	if max <= 0 {
		max = 4096
	}
	return &mapCounter{max: max, seen: make(map[string]struct{}, min(1024, max))}
}

func (m *mapCounter) Kind() string { return "map" }
func (m *mapCounter) Capped() bool { return m.capped }

func (m *mapCounter) Reset() {
	for k := range m.seen {
		delete(m.seen, k)
	}
	m.capped = false
}

func (m *mapCounter) Add(ip string) {
	if ip == "" {
		return
	}
	if m.capped {
		return
	}
	if _, ok := m.seen[ip]; ok {
		return
	}
	if len(m.seen) >= m.max {
		m.capped = true
		return
	}
	m.seen[ip] = struct{}{}
}

func (m *mapCounter) Estimate() int {
	return len(m.seen)
}

type bloomCounter struct {
	max    int
	bits   []uint64
	m      int
	capped bool
}

func newBloomCounter(max int, bloomBits int) *bloomCounter {
	if max <= 0 {
		max = 4096
	}
	if bloomBits <= 0 {
		bloomBits = 2048
	}
	if bloomBits < 256 {
		bloomBits = 256
	}
	m := ((bloomBits + 63) / 64) * 64
	return &bloomCounter{max: max, bits: make([]uint64, m/64), m: m}
}

func (b *bloomCounter) Kind() string { return "bloom" }
func (b *bloomCounter) Capped() bool { return b.capped }

func (b *bloomCounter) Reset() {
	for i := range b.bits {
		b.bits[i] = 0
	}
	b.capped = false
}

func (b *bloomCounter) Add(ip string) {
	if ip == "" {
		return
	}
	h := hash64String(ip)
	idx := int(h % uint64(b.m))
	word := idx >> 6
	bit := uint(idx & 63)
	b.bits[word] |= (uint64(1) << bit)
}

func (b *bloomCounter) Estimate() int {
	zeros := 0
	for _, w := range b.bits {
		zeros += 64 - bits.OnesCount64(w)
	}
	if zeros <= 0 {
		b.capped = true
		return b.max
	}
	m := float64(b.m)
	v := float64(zeros)
	est := -m * math.Log(v/m)
	if est < 0 {
		est = 0
	}
	if est > float64(b.max) {
		b.capped = true
		return b.max
	}
	return int(est + 0.5)
}

type hllCounter struct {
	max    int
	p      uint8
	m      int
	regs   []uint8
	capped bool
}

func newHLLCounter(max int, precision int) *hllCounter {
	if max <= 0 {
		max = 4096
	}
	if precision <= 0 {
		precision = 8
	}
	if precision < 4 {
		precision = 4
	}
	if precision > 16 {
		precision = 16
	}
	m := 1 << uint(precision)
	return &hllCounter{max: max, p: uint8(precision), m: m, regs: make([]uint8, m)}
}

func (h *hllCounter) Kind() string { return "hll" }
func (h *hllCounter) Capped() bool { return h.capped }

func (h *hllCounter) Reset() {
	for i := range h.regs {
		h.regs[i] = 0
	}
	h.capped = false
}

func (h *hllCounter) Add(ip string) {
	if ip == "" {
		return
	}
	hv := hash64String(ip)
	idx := int(hv & uint64(h.m-1))
	w := hv >> h.p

	lz := bits.LeadingZeros64(w) + 1
	maxRho := 64 - int(h.p) + 1
	if lz > maxRho {
		lz = maxRho
	}
	if uint8(lz) > h.regs[idx] {
		h.regs[idx] = uint8(lz)
	}
}

func (h *hllCounter) Estimate() int {
	m := float64(h.m)
	sum := 0.0
	zeros := 0
	for _, r := range h.regs {
		if r == 0 {
			zeros++
		}
		sum += math.Ldexp(1.0, -int(r))
	}
	alpha := 0.7213 / (1.0 + 1.079/m)
	est := alpha * m * m / sum

	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros))
	}

	if est < 0 {
		est = 0
	}
	if est > float64(h.max) {
		h.capped = true
		return h.max
	}
	return int(est + 0.5)
}
