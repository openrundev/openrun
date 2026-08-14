package system

import (
	"testing"
	"time"
)

func TestHumanDuration(t *testing.T) {
	cases := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"recent_zero", 0, "recently"},
		{"recent_subsec", 500 * time.Millisecond, "recently"},
		{"one_second", 1 * time.Second, "1s ago"},
		{"multi_seconds", 42 * time.Second, "42s ago"},
		{"one_minute", 1 * time.Minute, "1m ago"},
		{"minute_and_seconds", 1*time.Minute + 1*time.Second, "1m 1s ago"},
		{"hour_rounds_minute_precision_down", 1*time.Hour + 1*time.Second, "1h ago"},
		{"one_hour_one_minute", 1*time.Hour + 1*time.Minute + 1*time.Second, "1h 1m ago"},
		{"under_six_hours_round_up_to_hour", 5*time.Hour + 59*time.Minute + 31*time.Second, "6h ago"},
		{"six_hours_round_to_hour", 6*time.Hour + 1*time.Minute, "6h ago"},
		{"one_day", 24 * time.Hour, "1d ago"},
		{"days_and_hours", 49 * time.Hour, "2d 1h ago"},
		{"negative_seconds", -30 * time.Second, "-30s ago"},
		{"negative_recently", -500 * time.Millisecond, "-recently"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HumanDuration(tc.d, 0)
			if got != tc.want {
				t.Fatalf("HumanDuration(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}

	// resolution caps the units at the most significant one: hours never
	// accumulate past a day
	single := []struct {
		name string
		d    time.Duration
		want string
	}{
		{"res1_day_strips_hours", 49 * time.Hour, "2d ago"},
		{"res1_many_hours_become_days", 1540 * time.Hour, "64d ago"},
		{"res1_one_day", 24 * time.Hour, "1d ago"},
		{"res1_hours", 3*time.Hour + 20*time.Minute, "3h ago"},
		{"res1_minutes", 1*time.Minute + 30*time.Second, "1m ago"},
		{"res1_subsec", 200 * time.Millisecond, "recently"},
	}
	for _, tc := range single {
		t.Run(tc.name, func(t *testing.T) {
			got := HumanDuration(tc.d, 1)
			if got != tc.want {
				t.Fatalf("HumanDuration(%v, 1) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}
