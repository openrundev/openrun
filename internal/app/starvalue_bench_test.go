// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/openrundev/openrun/internal/app/starlark_type"
	sdk "github.com/openrundev/openrun/pkg/plugin"
	"go.starlark.net/starlark"
	"google.golang.org/protobuf/proto"
)

// Benchmarks comparing the three candidate value encodings for in-process
// plugin calls, measured as the full round trip a call pays: starlark value
// (argument) -> Go value handed to the plugin -> starlark value (result).
//
//   - direct:  starToGoValue / goValueToStar (the chosen bridge)
//   - wire:    starToWire -> DecodeValue / EncodeValue -> wireToStar (the
//     gRPC path's codec, without serialization)
//   - wireser: wire plus proto.Marshal/Unmarshal (what an external provider
//     call pays for encoding, excluding gRPC/process overhead)
//   - json:    UnmarshalStarlark -> json.Marshal -> json.Unmarshal ->
//     MarshalStarlark (the JSON approach; lossy: ints arrive as float64)
//
// Run with: go test -bench BenchmarkBridge -run xx ./internal/app/

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

func BenchmarkBridge(b *testing.B) {
	for name, payload := range benchPayloads() {
		b.Run("direct/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				goVal, err := starToGoValue(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := goValueToStar(goVal, 0, nil); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wire/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := starToWire(payload, 0)
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
				if _, err := wireToStar(enc2, nil, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("wireser/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				enc, err := starToWire(payload, 0)
				if err != nil {
					b.Fatal(err)
				}
				data, err := proto.Marshal(enc)
				if err != nil {
					b.Fatal(err)
				}
				var decoded = enc.ProtoReflect().New().Interface()
				if err := proto.Unmarshal(data, decoded); err != nil {
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
				data2, err := proto.Marshal(enc2)
				if err != nil {
					b.Fatal(err)
				}
				var decoded2 = enc2.ProtoReflect().New().Interface()
				if err := proto.Unmarshal(data2, decoded2); err != nil {
					b.Fatal(err)
				}
				if _, err := wireToStar(enc2, nil, nil, 0); err != nil {
					b.Fatal(err)
				}
			}
		})
		b.Run("json/"+name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				goVal, err := starlark_type.UnmarshalStarlark(payload)
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
				if _, err := starlark_type.MarshalStarlark(decoded); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
