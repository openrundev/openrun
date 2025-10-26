// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
	"strings"
	"time"
)

// HumanDuration returns a human readable duration string
func HumanDuration(d time.Duration) string {
	if d >= 0 && d < time.Second {
		return "recently"
	}
	if d < 0 {
		return "-" + HumanDuration(-d)
	}

	// Round to whole seconds so we don't show sub-second noise.
	if d < time.Hour {
		d = d.Round(time.Second)
	} else if d < 6*time.Hour {
		d = d.Round(time.Minute)
	} else {
		d = d.Round(time.Hour)
	}

	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour

	hours := d / time.Hour
	d -= hours * time.Hour

	minutes := d / time.Minute
	d -= minutes * time.Minute

	seconds := d / time.Second

	var parts []string
	add := func(n int64, singular, plural string) {
		if n == 0 {
			return
		}
		if n == 1 {
			parts = append(parts, fmt.Sprintf("%d %s", n, singular))
		} else {
			parts = append(parts, fmt.Sprintf("%d %s", n, plural))
		}
	}

	add(int64(days), "day", "days")
	add(int64(hours), "hour", "hours")
	add(int64(minutes), "minute", "minutes")
	add(int64(seconds), "second", "seconds")

	return strings.Join(parts, " ") + " ago"
}
