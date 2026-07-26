package mathx_test

import (
	"testing"

	"gitlab.com/nathanmblima/dynasmon-seagull/agent/internal/mathx"
)

func TestRound2Truncates(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1.238, 1.23},
		{1.231, 1.23},
		{2.5, 2.5},
		{10, 10},
	}
	for _, c := range cases {
		if got := mathx.Round2(c.in); got != c.want {
			t.Errorf("Round2(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRound2HalfUpRounds(t *testing.T) {
	cases := []struct {
		in   float64
		want float64
	}{
		{0, 0},
		{1.238, 1.24},
		{1.231, 1.23},
		{2.5, 2.5},
	}
	for _, c := range cases {
		if got := mathx.Round2HalfUp(c.in); got != c.want {
			t.Errorf("Round2HalfUp(%v) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestRound2HalfUpNaN(t *testing.T) {
	var zero float64
	nan := zero / zero
	if got := mathx.Round2HalfUp(nan); got != 0 {
		t.Errorf("Round2HalfUp(NaN) = %v, want 0", got)
	}
}
