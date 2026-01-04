package ddos

import (
	"math"
)

func entropyNormFromCounts(counts []int) float64 {
	if len(counts) <= 1 {
		return 0
	}
	total := 0
	for _, c := range counts {
		if c > 0 {
			total += c
		}
	}
	if total <= 0 {
		return 0
	}

	h := 0.0
	for _, c := range counts {
		if c <= 0 {
			continue
		}
		p := float64(c) / float64(total)
		h -= p * math.Log2(p)
	}
	den := math.Log2(float64(len(counts)))
	if den <= 0 {
		return 0
	}
	v := h / den
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func srcEntropyNorm(totalPkts int, top []TopKStrItem) float64 {
	if totalPkts <= 0 {
		return 0
	}
	sumTop := 0
	counts := make([]int, 0, len(top)+1)
	for _, it := range top {
		if it.Count > 0 {
			counts = append(counts, it.Count)
			sumTop += it.Count
		}
	}
	other := totalPkts - sumTop
	if other > 0 {
		counts = append(counts, other)
	}
	return entropyNormFromCounts(counts)
}

type PortEntropy struct {
	EntropyNorm float64
	Distinct    int
	TopPort     int
	TopShare    float64
}

func portEntropy(totalPkts int, ports []TopKIntItem) PortEntropy {
	if totalPkts <= 0 {
		return PortEntropy{}
	}
	sumTop := 0
	counts := make([]int, 0, len(ports)+1)
	topPort := 0
	topVal := 0
	for _, it := range ports {
		if it.Count <= 0 {
			continue
		}
		counts = append(counts, it.Count)
		sumTop += it.Count
		if it.Count > topVal {
			topVal = it.Count
			topPort = it.Key
		}
	}
	other := totalPkts - sumTop
	if other > 0 {
		counts = append(counts, other)
	}

	distinct := len(ports)
	if other > 0 {
		distinct++
	}

	topShare := 0.0
	if totalPkts > 0 && topVal > 0 {
		topShare = float64(topVal) / float64(totalPkts)
		if topShare < 0 {
			topShare = 0
		}
		if topShare > 1 {
			topShare = 1
		}
	}

	return PortEntropy{
		EntropyNorm: entropyNormFromCounts(counts),
		Distinct:    distinct,
		TopPort:     topPort,
		TopShare:    topShare,
	}
}
