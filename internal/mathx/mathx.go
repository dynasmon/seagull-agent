package mathx

func Round2(v float64) float64 {
	return float64(int(v*100)) / 100
}

func Round2HalfUp(v float64) float64 {
	if v != v {
		return 0
	}
	return float64(int(v*100+0.5)) / 100
}
