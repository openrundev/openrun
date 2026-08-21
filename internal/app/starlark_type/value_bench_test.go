// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package starlark_type

import (
	"encoding/json/v2"
	"fmt"
	"testing"

	sdk "github.com/openrundev/openrun/pkg/plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	"go.starlark.net/starlark"
	"google.golang.org/protobuf/proto"
)

// Benchmarks comparing the three candidate value encodings for in-process
// plugin calls, measured as the full round trip a call pays: starlark value
// (argument) -> Go value handed to the plugin -> starlark value (result).
//
//   - direct:  ToPlugin / FromPlugin (the chosen bridge)
//   - wire:    ToWire -> DecodeValue / EncodeValue -> FromWire (the
//     gRPC path's codec, without serialization)
//   - wireser: wire plus proto.Marshal/Unmarshal (what an external provider
//     call pays for encoding, excluding gRPC/process overhead)
//   - json:    application ToGo -> json.Marshal -> json.Unmarshal -> FromGo
//     (the JSON approach; lossy: ints arrive as float64)
//
// Run with: go test -bench BenchmarkBridge -run '^$' ./internal/app/starlark_type/

func benchRecord(i int) *starlark.Dict {
	d := starlark.NewDict(8)
	_ = d.SetKey(starlark.String("id"), starlark.String(fmt.Sprintf("app_prd_%020d", i)))
	_ = d.SetKey(starlark.String("name"), starlark.String("my application"))
	_ = d.SetKey(starlark.String("path"), starlark.String("/apps/example"))
	_ = d.SetKey(starlark.String("version"), starlark.MakeInt(i))
	_ = d.SetKey(starlark.String("active"), starlark.Bool(true))
	_ = d.SetKey(starlark.String("size"), starlark.Float(1234.5))
	_ = d.SetKey(starlark.String("tags"), starlark.NewList([]starlark.Value{
		starlark.String("web"), starlark.String("prod"), starlark.String("team-a"),
	}))
	meta := starlark.NewDict(2)
	_ = meta.SetKey(starlark.String("spec"), starlark.String("proxy"))
	_ = meta.SetKey(starlark.String("branch"), starlark.String("main"))
	_ = d.SetKey(starlark.String("meta"), meta)
	return d
}

func benchPayloads() map[string]starlark.Value {
	small := starlark.Tuple{starlark.String("mytable"), starlark.MakeInt(42)}

	records := make([]starlark.Value, 200)
	for i := range records {
		records[i] = benchRecord(i)
	}

	return map[string]starlark.Value{
		"small":  small,
		"record": benchRecord(3),
		"list":   starlark.NewList(records),
	}
}

func benchGoPayloads(tb testing.TB) map[string]any {
	tb.Helper()
	values := make(map[string]any, len(benchPayloads()))
	for name, payload := range benchPayloads() {
		value, err := ToPlugin(payload, 0)
		if err != nil {
			tb.Fatal(err)
		}
		values[name] = value
	}
	return values
}

// BenchmarkStarlarkToGo measures arguments entering a plugin. The wire case
// includes construction and decoding of the protobuf value tree, but not
// serialization or RPC overhead.
func BenchmarkStarlarkToGo(b *testing.B) {
	for name, payload := range benchPayloads() {
		b.Run("direct/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := ToPlugin(payload, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wire/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := ToWire(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := sdk.DecodeValue(enc); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

// BenchmarkGoToStarlark measures plugin results entering Starlark. The wire
// case includes construction and decoding of the protobuf value tree, but not
// serialization or RPC overhead.
func BenchmarkGoToStarlark(b *testing.B) {
	for name, payload := range benchGoPayloads(b) {
		b.Run("direct/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				if _, err := FromPlugin(payload, 0, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wire/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := sdk.EncodeValue(payload)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := FromWire(enc, nil, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkBridge(b *testing.B) {
	for name, payload := range benchPayloads() {
		b.Run("direct/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				goVal, err := ToPlugin(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := FromPlugin(goVal, 0, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wire/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := ToWire(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				goVal, err := sdk.DecodeValue(enc)
				if err != nil {
					b.Fatal(err)
				}
				enc2, err := sdk.EncodeValue(goVal)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := FromWire(enc2, nil, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wireser/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := ToWire(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				data, err := proto.Marshal(enc)
				if err != nil {
					b.Fatal(err)
				}
				decoded := new(pb.StarValue)
				if err := proto.Unmarshal(data, decoded); err != nil {
					b.Fatal(err)
				}
				goVal, err := sdk.DecodeValue(decoded)
				if err != nil {
					b.Fatal(err)
				}
				enc2, err := sdk.EncodeValue(goVal)
				if err != nil {
					b.Fatal(err)
				}
				data2, err := proto.Marshal(enc2)
				if err != nil {
					b.Fatal(err)
				}
				decoded2 := new(pb.StarValue)
				if err := proto.Unmarshal(data2, decoded2); err != nil {
					b.Fatal(err)
				}
				if _, err := FromWire(decoded2, nil, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("json/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				goVal, err := ToGo(payload)
				if err != nil {
					b.Fatal(err)
				}
				data, err := json.Marshal(goVal)
				if err != nil {
					b.Fatal(err)
				}
				var decoded any
				if err := json.Unmarshal(data, &decoded); err != nil {
					b.Fatal(err)
				}
				if _, err := FromGo(decoded); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
