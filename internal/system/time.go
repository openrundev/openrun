// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package system

import (
	"fmt"
	"strings"
	"time"
)

// HumanDuration returns a compact human readable duration string:
// "1d 2h ago" style short units. resolution caps how many units are
// included, most significant first: 1 gives "105d ago", 2 "105d 3h ago".
// 0 keeps every non-zero unit after rounding. Durations always collapse
// into the largest unit, so hours never accumulate past a day ("1540
// hours" renders as days)
func HumanDuration(d time.Duration, resolution int) string {
	if d >= 0 && d < time.Second {
		return "recently"
	}
	if d < 0 {
		return "-" + HumanDuration(-d, resolution)
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
	add := func(n int64, unit string) {
		if n == 0 {
			return
		}
		parts = append(parts, fmt.Sprintf("%d%s", n, unit))
	}

	add(int64(days), "d")
	add(int64(hours), "h")
	add(int64(minutes), "m")
	add(int64(seconds), "s")

	if resolution > 0 && len(parts) > resolution {
		parts = parts[:resolution]
	}
	return strings.Join(parts, " ") + " ago"
}
