// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package plugin

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"time"

	goplugin "github.com/hashicorp/go-plugin"
	pb "github.com/openrundev/openrun/pkg/plugin/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// ServeConfig configures a Starlark plugin provider process.
type ServeConfig struct {
	// Modules maps each module name served by this provider to its
	// definition. A module "store" is loaded by apps as "store.in" (or
	// "store.ex" to require the external build).
	Modules map[string]ModuleDef

	// ProviderVersion is the provider's release version, reported via
	// Describe.
	ProviderVersion string
}

// Serve runs the provider plugin. It is called from a provider executable's
// main function and blocks until the server side closes the plugin. The
// OPENRUN_PROVIDER_LOG_LEVEL environment variable (set by the server from its
// own log level) controls provider log verbosity.
func Serve(config *ServeConfig) {
	// `<provider> export <dir>` copies the running executable into <dir> and
	// exits. Provider OCI images are FROM scratch with no shell, so on
	// Kubernetes an init container runs the provider binary itself to place
	// it into the shared volume the server discovers via
	// plugin_providers.preinstalled_dir.
	if len(os.Args) >= 2 && os.Args[1] == "export" {
		if err := exportExecutable(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "export failed: %s\n", err)
			os.Exit(1)
		}
		return
	}

	host, err := NewHost(config, newServeLogger(os.Getenv("OPENRUN_PROVIDER_LOG_LEVEL")))
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid plugin provider config: %s\n", err)
		os.Exit(1)
	}
	srv := &providerServer{config: config, host: host}

	goplugin.Serve(&goplugin.ServeConfig{
		HandshakeConfig: Handshake,
		VersionedPlugins: map[int]goplugin.PluginSet{
			ProtocolVersion: {PluginName: &providerPlugin{srv: srv}},
		},
		GRPCServer: func(opts []grpc.ServerOption) *grpc.Server {
			opts = append(opts, grpc.MaxRecvMsgSize(MaxMessageSize), grpc.MaxSendMsgSize(MaxMessageSize))
			return goplugin.DefaultGRPCServer(opts)
		},
	})

	// The server closed the plugin (app close or reload): run the module
	// shutdown callbacks before the process exits
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	host.Close(ctx)
}

// exportExecutable copies the running provider executable into the target
// directory, keeping its base name (openrun-plugin-<name>). The copy is
// atomic (temp file + rename) and mode 0555, so a restarted init container
// can re-export over a previous copy and the server user can execute it
// regardless of the exporting user.
func exportExecutable(args []string) error {
	if len(args) != 1 || args[0] == "" {
		return errors.New("usage: export <target-dir>")
	}
	self, err := os.Executable()
	if err != nil {
		return err
	}
	data, err := os.ReadFile(self)
	if err != nil {
		return err
	}
	targetDir := args[0]
	if err := os.MkdirAll(targetDir, 0o755); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(targetDir, ".export-*")
	if err != nil {
		return err
	}
	tmpPath := tmp.Name()
	_, writeErr := tmp.Write(data)
	closeErr := tmp.Close()
	if err := errors.Join(writeErr, closeErr); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return err
	}
	if err := os.Chmod(tmpPath, 0o555); err != nil { //nolint:gosec // provider must be executable by the server user
		os.Remove(tmpPath) //nolint:errcheck
		return err
	}
	target := filepath.Join(targetDir, filepath.Base(self))
	if err := os.Rename(tmpPath, target); err != nil {
		os.Remove(tmpPath) //nolint:errcheck
		return err
	}
	fmt.Printf("exported %s\n", target)
	return nil
}

// validateConfig checks every declared function resolves to a method with
// the Func signature on the module's instance type, so a typo fails the
// provider at startup instead of a user's request at runtime.
func validateConfig(config *ServeConfig) error {
	for moduleName, def := range config.Modules {
		if def.Builder == nil {
			return fmt.Errorf("module %s has no builder", moduleName)
		}
		probe := def.Builder()
		for _, fn := range def.Functions {
			method := reflect.ValueOf(probe).MethodByName(fn.Method)
			if !method.IsValid() {
				return fmt.Errorf("module %s function %s: method %s not found", moduleName, fn.Name, fn.Method)
			}
			if _, ok := method.Interface().(Func); !ok {
				return fmt.Errorf("module %s function %s: method %s does not have the plugin function signature", moduleName, fn.Name, fn.Method)
			}
		}
	}
	return nil
}

// moduleInstance is one initialized (module, account) instance.
type moduleInstance struct {
	module    Module
	functions map[string]Func
}

func instanceKey(module, account string) string {
	return module + "\x00" + account
}

// providerServer implements the provider-side gRPC service as a codec shim
// over Host: wire values are decoded at the edges, all semantics live in the
// Host. The server launches one provider process per app, so app identity is
// process state established by InitApp.
type providerServer struct {
	pb.UnimplementedPluginProviderServer

	config *ServeConfig
	host   *Host
}

func (s *providerServer) Describe(ctx context.Context, req *pb.DescribeRequest) (*pb.DescribeResponse, error) {
	modules := make([]*pb.ModuleManifest, 0, len(s.config.Modules))
	for _, name := range slices.Sorted(maps.Keys(s.config.Modules)) {
		def := s.config.Modules[name]
		manifest := &pb.ModuleManifest{Name: name}
		for _, fn := range def.Functions {
			manifest.Functions = append(manifest.Functions, &pb.FunctionManifest{
				Name:   fn.Name,
				IsRead: fn.Type == READ,
			})
		}
		if len(def.Constants) > 0 {
			constants, err := EncodeValueMap(def.Constants)
			if err != nil {
				return nil, status.Errorf(codes.Internal, "module %s constants: %s", name, err)
			}
			manifest.Constants = constants
		}
		modules = append(modules, manifest)
	}
	return &pb.DescribeResponse{
		ProviderVersion: s.config.ProviderVersion,
		Modules:         modules,
	}, nil
}

func (s *providerServer) InitApp(ctx context.Context, req *pb.InitAppRequest) (*pb.InitAppResponse, error) {
	err := s.host.InitApp(AppInfo{
		AppId:     req.GetAppId(),
		AppPath:   req.GetAppPath(),
		IsDev:     req.GetIsDev(),
		AppSchema: req.GetAppSchema(),
	})
	if err != nil {
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	}
	return &pb.InitAppResponse{}, nil
}

func (s *providerServer) InitModule(ctx context.Context, req *pb.InitModuleRequest) (*pb.InitModuleResponse, error) {
	settings, err := DecodeValueMap(req.GetSettings())
	if err != nil {
		return &pb.InitModuleResponse{Error: fmt.Sprintf("invalid module settings: %s", err)}, nil
	}

	err = s.host.InitModule(ctx, req.GetModule(), req.GetAccount(), settings)
	switch {
	case err == nil:
		return &pb.InitModuleResponse{}, nil
	case errors.Is(err, ErrUnknownModule):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrAppNotInited):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	default:
		return &pb.InitModuleResponse{Error: err.Error()}, nil
	}
}

func (s *providerServer) Call(ctx context.Context, req *pb.CallRequest) (*pb.CallResponse, error) {
	args := make([]any, len(req.GetArgs()))
	for i, arg := range req.GetArgs() {
		dec, err := DecodeValue(arg)
		if err != nil {
			return &pb.CallResponse{Error: fmt.Sprintf("invalid argument %d: %s", i, err), ErrorCode: 1}, nil
		}
		args[i] = dec
	}
	kwargs := make([]Kwarg, len(req.GetKwargs()))
	for i, kwarg := range req.GetKwargs() {
		dec, err := DecodeValue(kwarg.GetValue())
		if err != nil {
			return &pb.CallResponse{Error: fmt.Sprintf("invalid keyword argument %s: %s", kwarg.GetName(), err), ErrorCode: 1}, nil
		}
		kwargs[i] = Kwarg{Name: kwarg.GetName(), Value: dec}
	}

	thread := req.GetThread()
	result, err := s.host.Call(ctx, &HostCall{
		Module:   req.GetModule(),
		Account:  req.GetAccount(),
		Function: req.GetFunction(),
		Args:     args,
		Kwargs:   kwargs,
		Thread: ThreadState{
			RequestId:   thread.GetRequestId(),
			UserId:      thread.GetUserId(),
			UserSubject: thread.GetUserSubject(),
			UserEmail:   thread.GetUserEmail(),
			Groups:      thread.GetGroups(),
			AppUrl:      thread.GetAppUrl(),
		},
		SessionId: req.GetSessionId(),
	})
	switch {
	case errors.Is(err, ErrModuleNotInited):
		return nil, status.Error(codes.FailedPrecondition, err.Error())
	case errors.Is(err, ErrUnknownFunction):
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	var resp *pb.CallResponse
	switch {
	case err != nil:
		resp = &pb.CallResponse{Error: err.Error(), ErrorCode: 1}
		if perr, ok := err.(*ProviderError); ok && perr.Code != 0 {
			resp.ErrorCode = perr.Code
		}
	case result.Cursor != nil:
		resp = &pb.CallResponse{Value: &pb.StarValue{Kind: &pb.StarValue_Cursor{Cursor: &pb.Cursor{
			CursorId: result.Cursor.CursorId,
			TypeName: result.Cursor.TypeName,
			LeakKey:  result.Cursor.LeakKey,
			Stream:   result.Cursor.Stream,
		}}}}
	default:
		value, encErr := EncodeValue(result.Value)
		if encErr != nil {
			resp = &pb.CallResponse{Error: fmt.Sprintf("plugin function %s returned a non-transportable value: %s", req.GetFunction(), encErr), ErrorCode: 1}
		} else {
			resp = &pb.CallResponse{Value: value}
		}
	}
	resp.StrictKeys = result.StrictKeys
	return resp, nil
}

func (s *providerServer) CursorNext(ctx context.Context, req *pb.CursorNextRequest) (*pb.CursorNextResponse, error) {
	items, done, err := s.host.CursorNext(ctx, req.GetSessionId(), req.GetCursorId(), int(req.GetMaxItems()))
	if err != nil {
		return &pb.CursorNextResponse{Error: err.Error()}, nil
	}

	encoded := make([]*pb.StarValue, len(items))
	for i, item := range items {
		enc, encErr := EncodeValue(item)
		if encErr != nil {
			return &pb.CursorNextResponse{Error: fmt.Sprintf("non-transportable cursor item: %s", encErr)}, nil
		}
		encoded[i] = enc
	}
	return &pb.CursorNextResponse{Items: encoded, Done: done}, nil
}

func (s *providerServer) CursorClose(ctx context.Context, req *pb.CursorCloseRequest) (*pb.CursorCloseResponse, error) {
	if err := s.host.CursorClose(ctx, req.GetSessionId(), req.GetCursorId()); err != nil {
		return &pb.CursorCloseResponse{Error: err.Error()}, nil
	}
	return &pb.CursorCloseResponse{}, nil
}

func (s *providerServer) EndSession(ctx context.Context, req *pb.EndSessionRequest) (*pb.EndSessionResponse, error) {
	if err := s.host.EndSession(ctx, req.GetSessionId()); err != nil {
		return &pb.EndSessionResponse{Error: err.Error()}, nil
	}
	return &pb.EndSessionResponse{}, nil
}

func (s *providerServer) CheckHealth(ctx context.Context, req *pb.CheckHealthRequest) (*pb.CheckHealthResponse, error) {
	return &pb.CheckHealthResponse{}, nil
}
