package ddos

import "sort"

type TopKStr struct {
	k     int
	items map[string]int
}

type TopKStrItem struct {
	Key   string `json:"ip"`
	Count int    `json:"packets"`
}

func NewTopKStr(k int) *TopKStr {
	if k <= 0 {
		k = 10
	}
	return &TopKStr{k: k, items: make(map[string]int, k*2)}
}

func (t *TopKStr) Reset() {
	for k := range t.items {
		delete(t.items, k)
	}
}

func (t *TopKStr) Add(key string, inc int) {
	if key == "" || inc <= 0 {
		return
	}
	if v, ok := t.items[key]; ok {
		t.items[key] = v + inc
		return
	}
	if len(t.items) < t.k {
		t.items[key] = inc
		return
	}

	minKey := ""
	minVal := 0
	first := true
	for k, v := range t.items {
		if first || v < minVal {
			minVal = v
			minKey = k
			first = false
		}
	}
	if minKey == "" {
		return
	}
	delete(t.items, minKey)
	t.items[key] = minVal + inc
}

func (t *TopKStr) ItemsSorted() []TopKStrItem {
	out := make([]TopKStrItem, 0, len(t.items))
	for k, v := range t.items {
		out = append(out, TopKStrItem{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > t.k {
		out = out[:t.k]
	}
	return out
}

type TopKInt struct {
	k     int
	items map[int]int
}

type TopKIntItem struct {
	Key   int
	Count int
}

func NewTopKInt(k int) *TopKInt {
	if k <= 0 {
		k = 10
	}
	return &TopKInt{k: k, items: make(map[int]int, k*2)}
}

func (t *TopKInt) Add(key int, inc int) {
	if key < 0 || inc <= 0 {
		return
	}
	if v, ok := t.items[key]; ok {
		t.items[key] = v + inc
		return
	}
	if len(t.items) < t.k {
		t.items[key] = inc
		return
	}

	minKey := 0
	minVal := 0
	first := true
	for k, v := range t.items {
		if first || v < minVal {
			minVal = v
			minKey = k
			first = false
		}
	}
	delete(t.items, minKey)
	t.items[key] = minVal + inc
}

func (t *TopKInt) ItemsSorted() []TopKIntItem {
	out := make([]TopKIntItem, 0, len(t.items))
	for k, v := range t.items {
		out = append(out, TopKIntItem{Key: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count == out[j].Count {
			return out[i].Key < out[j].Key
		}
		return out[i].Count > out[j].Count
	})
	if len(out) > t.k {
		out = out[:t.k]
	}
	return out
}
