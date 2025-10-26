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
		{"one_second", 1 * time.Second, "1 second ago"},
		{"multi_seconds", 42 * time.Second, "42 seconds ago"},
		{"one_minute", 1 * time.Minute, "1 minute ago"},
		{"minute_and_seconds", 1*time.Minute + 1*time.Second, "1 minute 1 second ago"},
		{"hour_rounds_minute_precision_down", 1*time.Hour + 1*time.Second, "1 hour ago"},
		{"one_hour_one_minute", 1*time.Hour + 1*time.Minute + 1*time.Second, "1 hour 1 minute ago"},
		{"under_six_hours_round_up_to_hour", 5*time.Hour + 59*time.Minute + 31*time.Second, "6 hours ago"},
		{"six_hours_round_to_hour", 6*time.Hour + 1*time.Minute, "6 hours ago"},
		{"one_day", 24 * time.Hour, "1 day ago"},
		{"days_and_hours", 49 * time.Hour, "2 days 1 hour ago"},
		{"negative_seconds", -30 * time.Second, "-30 seconds ago"},
		{"negative_recently", -500 * time.Millisecond, "-recently"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := HumanDuration(tc.d)
			if got != tc.want {
				t.Fatalf("HumanDuration(%v) = %q, want %q", tc.d, got, tc.want)
			}
		})
	}
}
