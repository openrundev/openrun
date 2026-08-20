// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"sync"
)

type streamItem struct {
	value any
	err   error
}

// PushCursor adapts a push-style stream function (repeatedly calling yield
// with values, like a range-over-func iterator) into a pull-based Cursor.
// The stream function runs in its own goroutine, started lazily on the first
// Next; it stops when it returns, yields an error, or the cursor is closed.
// Next returns the first available item promptly (it does not wait to fill a
// batch), so live streams flush without delay.
func PushCursor(typeName, leakKey string, stream bool, seq func(yield func(any, error) bool)) *Cursor {
	ch := make(chan streamItem)
	stopped := make(chan struct{})
	var startOnce, stopOnce sync.Once

	start := func() {
		go func() {
			defer close(ch)
			seq(func(v any, err error) bool {
				select {
				case ch <- streamItem{value: v, err: err}:
					return err == nil
				case <-stopped:
					return false
				}
			})
		}()
	}
	stop := func() {
		stopOnce.Do(func() { close(stopped) })
	}

	return &Cursor{
		TypeName: typeName,
		LeakKey:  leakKey,
		Stream:   stream,
		Next: func(ctx context.Context, max int) ([]any, bool, error) {
			startOnce.Do(start)
			if max <= 0 {
				max = 100
			}

			// Block for the first item, then take whatever is immediately
			// available up to max
			var items []any
			select {
			case item, ok := <-ch:
				if !ok {
					return nil, true, nil
				}
				if item.err != nil {
					stop()
					return nil, false, item.err
				}
				items = append(items, item.value)
			case <-ctx.Done():
				stop()
				return nil, false, ctx.Err()
			}

			for len(items) < max {
				select {
				case item, ok := <-ch:
					if !ok {
						return items, true, nil
					}
					if item.err != nil {
						stop()
						return nil, false, item.err
					}
					items = append(items, item.value)
				default:
					return items, false, nil
				}
			}
			return items, false, nil
		},
		Close: func(ctx context.Context) error {
			stop()
			return nil
		},
	}
}
