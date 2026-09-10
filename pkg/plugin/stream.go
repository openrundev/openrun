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
// Close cancels the producer context and waits for it to return. Producers
// must use that context for blocking work and stop when yield returns false.
func PushCursor(parent context.Context, typeName, leakKey string, stream bool, seq func(context.Context, func(any, error) bool)) *Cursor {
	producerCtx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	ch := make(chan streamItem)
	stopped := make(chan struct{})
	var startOnce, stopOnce sync.Once

	start := func() {
		go func() {
			defer close(done)
			defer close(ch)
			defer cancel()
			seq(producerCtx, func(v any, err error) bool {
				select {
				case ch <- streamItem{value: v, err: err}:
					return err == nil
				case <-stopped:
					return false
				case <-producerCtx.Done():
					return false
				}
			})
		}()
	}
	stop := func() {
		stopOnce.Do(func() { cancel(); close(stopped) })
		startOnce.Do(func() { close(ch); close(done) })
	}

	// An error arriving while a batch is being drained is held back so the
	// items collected before it are delivered first; the next call reports
	// it. Otherwise a producer's final output would be lost whenever its
	// terminal error (a command's exit status) lands in the same batch
	var pendingErr error

	return &Cursor{
		TypeName: typeName,
		LeakKey:  leakKey,
		Stream:   stream,
		Next: func(ctx context.Context, max int) ([]any, bool, error) {
			if pendingErr != nil {
				err := pendingErr
				pendingErr = nil
				stop()
				return nil, false, err
			}
			select {
			case <-stopped:
				return nil, true, nil
			case <-ctx.Done():
				stop()
				return nil, false, ctx.Err()
			default:
			}
			startOnce.Do(start)
			if max <= 0 {
				max = 100
			}

			// Block for the first item, then take whatever is immediately
			// available up to max
			var items []any
			select {
			case <-stopped:
				return nil, true, nil
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
						pendingErr = item.err
						return items, false, nil
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
			<-done
			return nil
		},
	}
}
