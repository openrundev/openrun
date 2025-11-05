// Copyright (c) ClaceIO, LLC
// SPDX-License-Identifier: Apache-2.0

package app

import (
	"bytes"
	"cmp"
	"encoding/json"
	"fmt"
	"net/http"
	"path"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi"
	"github.com/openrundev/openrun/internal/app/action"
	"github.com/openrundev/openrun/internal/app/apptype"
	"github.com/openrundev/openrun/internal/app/starlark_type"
	"github.com/openrundev/openrun/internal/system"
	"github.com/openrundev/openrun/internal/types"
	"go.starlark.net/starlark"
	"go.starlark.net/starlarkstruct"
)

var (
	REAL_IP_HEADER   = "X-Real-IP"
	FORWARDED_HEADER = "X-Forwarded-For"

	CONTENT_TYPE_JSON = []string{"application/json"}
	CONTENT_TYPE_TEXT = []string{"text/plain"}

	SERVER_NAME       = []string{"OpenRun"}
	VARY_HEADER_VALUE = []string{"HX-Request"}
)

func init() {
	REAL_IP_HEADER = http.CanonicalHeaderKey(REAL_IP_HEADER)
	FORWARDED_HEADER = http.CanonicalHeaderKey(FORWARDED_HEADER)
}

func (a *App) earlyHints(w http.ResponseWriter, r *http.Request) {
	sendHint := false
	for _, f := range a.sourceFS.StaticFiles() {
		if strings.HasSuffix(f, ".css") {
			sendHint = true
			w.Header().Add("Link", fmt.Sprintf("<%s>; rel=preload; as=style",
				path.Join(a.Path, a.sourceFS.HashName(f))))
		} else if strings.HasSuffix(f, ".js") {
			if !strings.HasSuffix(f, "sse.js") {
				sendHint = true
				w.Header().Add("Link", fmt.Sprintf("<%s>; rel=preload; as=script",
					path.Join(a.Path, a.sourceFS.HashName(f))))
			}
		}
	}

	if sendHint {
		a.Trace().Msg("Sending early hints for static files")
		w.WriteHeader(http.StatusEarlyHints)
	}
}

func getRequestUrl(r *http.Request) string {
	if r.TLS != nil {
		return "https://" + r.Host
	} else {
		return "http://" + r.Host
	}
}

// pooled holds one encoder and its buffer.
type pooled struct {
	enc *json.Encoder
	buf *bytes.Buffer
}

var encoderPool = sync.Pool{
	New: func() interface{} {
		buf := bytes.NewBuffer(make([]byte, 0, 512))
		return &pooled{
			enc: json.NewEncoder(buf),
			buf: buf,
		}
	},
}

func (a *App) createHandlerFunc(fullHtml, fragment string, handler starlark.Callable, rtype string) http.HandlerFunc {
	hasArgs := handler != nil && !strings.HasSuffix(handler.Name(), "_no_args")
	rtype = strings.ToUpper(rtype)
	goHandler := func(w http.ResponseWriter, r *http.Request) {
		thread := &starlark.Thread{
			Name:  a.Path,
			Print: func(_ *starlark.Thread, msg string) { fmt.Println(msg) },
		}

		// Save the request context in the starlark thread local
		thread.SetLocal(types.TL_CONTEXT, r.Context())
		if a.containerHandler != nil {
			thread.SetLocal(types.TL_CONTAINER_HANDLER, a.containerHandler)
			thread.SetLocal(types.TL_CONTAINER_URL, a.containerHandler.GetProxyUrl())
		}
		thread.SetLocal(types.TL_APP_URL, types.GetAppUrl(a.AppPathDomain(), a.serverConfig))

		header := r.Header
		isHtmxRequest := types.GetHTTPHeader(header, "Hx-Request") == "true" &&
			!(types.GetHTTPHeader(header, "Hx-Boosted") == "true") //nolint:staticcheck

		if a.serverConfig.System.EarlyHints && rtype == apptype.HTML_TYPE && a.codeConfig.Routing.EarlyHints && !a.IsDev &&
			r.Method == http.MethodGet &&
			types.GetHTTPHeader(header, "Sec-Fetch-Mode") == "navigate" &&
			!(isHtmxRequest && fragment != "") { //nolint:staticcheck
			// Prod mode, for a GET request from newer browsers on a top level HTML page, send http early hints
			a.earlyHints(w, r)
		}

		var requestData starlark_type.Request
		if hasArgs || rtype == apptype.HTML_TYPE {
			appPath := a.Path
			if appPath == "/" {
				appPath = ""
			}
			pagePath := r.URL.Path
			if pagePath == "/" {
				pagePath = ""
			}
			appUrl := getRequestUrl(r) + appPath
			requestData = starlark_type.Request{
				AppName:     a.Name,
				AppPath:     appPath,
				AppUrl:      appUrl,
				PagePath:    pagePath,
				PageUrl:     appUrl + pagePath,
				Method:      r.Method,
				IsDev:       a.IsDev,
				IsPartial:   isHtmxRequest,
				PushEvents:  a.codeConfig.Routing.PushEvents,
				HtmxVersion: a.codeConfig.Htmx.Version,
				Headers:     header,
				RemoteIP:    getRemoteIP(r),
			}

			chiContext := chi.RouteContext(r.Context())
			params := map[string]string{}
			if chiContext != nil && chiContext.URLParams.Keys != nil {
				for i, k := range chiContext.URLParams.Keys {
					params[k] = chiContext.URLParams.Values[i]
				}
			}
			requestData.UrlParams = params

			r.ParseForm() //nolint:errcheck // ignore error if no form data is passed
			requestData.Form = r.Form
			requestData.Query = r.URL.Query()
			requestData.PostForm = r.PostForm
		}

		var deferredCleanup func() error
		var handlerResponse any = map[string]any{} // no handler means empty Data map is passed into template
		if handler != nil {
			deferredCleanup = func() error {
				// Check for any deferred cleanups
				err := action.RunDeferredCleanup(thread)
				if err != nil {
					a.Error().Err(err).Msg("error cleaning up plugins")
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return err
				}
				return nil
			}

			eventStatus := types.EventStatusSuccess

			if a.auditInsert != nil {
				defer func() {
					op := system.GetThreadLocalKey(thread, types.TL_AUDIT_OPERATION)
					if op != "" {
						// Audit event was set, insert it
						event := types.AuditEvent{
							RequestId:  system.GetContextUserId(r.Context()),
							CreateTime: time.Now(),
							UserId:     system.GetContextUserId(r.Context()),
							AppId:      system.GetContextAppId(r.Context()),
							EventType:  types.EventTypeCustom,
							Status:     string(eventStatus),
						}

						event.Operation = op
						event.Target = system.GetThreadLocalKey(thread, types.TL_AUDIT_TARGET)
						event.Detail = system.GetThreadLocalKey(thread, types.TL_AUDIT_DETAIL)
						if err := a.auditInsert(&event); err != nil {
							a.Error().Err(err).Msg("error inserting audit event")
						}
					}
				}()
			}

			defer deferredCleanup() //nolint:errcheck

			// Call the handler function
			var ret starlark.Value
			var err error
			if hasArgs {
				ret, err = starlark.Call(thread, handler, starlark.Tuple{requestData}, nil)
			} else {
				ret, err = starlark.Call(thread, handler, nil, nil)
			}

			if err == nil {
				pluginErrLocal := thread.Local(types.TL_PLUGIN_API_FAILED_ERROR)
				if pluginErrLocal != nil {
					pluginErr := pluginErrLocal.(error)
					a.Error().Err(pluginErr).Msg("handler had plugin API failure")
					err = pluginErr // handle as if the handler had returned an error
				}
			}

			if err != nil {
				eventStatus = types.EventStatusFailure
				a.Error().Err(err).Msg("error calling handler")

				firstFrame := ""
				if evalErr, ok := err.(*starlark.EvalError); ok {
					// Iterate through the CallFrame stack for debugging information
					for i, frame := range evalErr.CallStack {
						a.Warn().Msgf("Function: %s, Position: %s\n", frame.Name, frame.Pos)
						if i == 0 {
							firstFrame = fmt.Sprintf("Function %s, Position %s", frame.Name, frame.Pos)
						}
					}
				}

				msg := err.Error()
				if firstFrame != "" && a.IsDev {
					msg = msg + " : " + firstFrame
				}

				if a.errorHandler == nil {
					// No err handler defined, abort
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}

				// error handler is defined, call it
				valueDict := starlark.Dict{}
				valueDict.SetKey(starlark.String("error"), starlark.String(msg)) //nolint:errcheck
				ret, err = starlark.Call(thread, a.errorHandler, starlark.Tuple{requestData, &valueDict}, nil)
				if err != nil {
					// error handler itself failed
					firstFrame := ""
					if evalErr, ok := err.(*starlark.EvalError); ok {
						// Iterate through the CallFrame stack for debugging information
						for i, frame := range evalErr.CallStack {
							a.Warn().Msgf("Function: %s, Position: %s\n", frame.Name, frame.Pos)
							if i == 0 {
								firstFrame = fmt.Sprintf("Function %s, Position %s", frame.Name, frame.Pos)
							}
						}
					}

					msg := err.Error()
					if firstFrame != "" && a.IsDev {
						msg = msg + " : " + firstFrame
					}
					http.Error(w, msg, http.StatusInternalServerError)
					return
				}
			}

			retStruct, ok := ret.(*starlarkstruct.Struct)
			if ok {
				// response type struct returned by handler Instead of template defined in
				// the route, use the template specified in the response
				done, err := a.handleResponse(retStruct, r, w, requestData, rtype, deferredCleanup)
				if done {
					return
				}

				http.Error(w, fmt.Sprintf("Error handling response: %s", err), http.StatusInternalServerError)
				return
			}

			if ret != nil {
				// Response from handler, or if handler failed, response from error_handler if defined
				handlerResponse, err = starlark_type.UnmarshalStarlark(ret)
				if err != nil {
					a.Error().Err(err).Msg("error converting response")
					http.Error(w, err.Error(), http.StatusInternalServerError)
					return
				}
			}
		}

		if deferredCleanup != nil {
			if deferredCleanup() != nil {
				return
			}
		}

		respHeader := w.Header()
		respHeader["Vary"] = VARY_HEADER_VALUE
		respHeader["Server"] = SERVER_NAME

		streamResponse, ok := handlerResponse.(map[string]any)
		if ok && streamResponse["is_stream"] == true {
			a.handleStreamResponse(w, r, rtype, cmp.Or(fragment, fullHtml), streamResponse)
			return
		}

		if rtype == apptype.JSON { //nolint:staticcheck
			// If the route type is JSON, then return the handler response as JSON
			respHeader["Content-Type"] = CONTENT_TYPE_JSON

			encoder := encoderPool.Get().(*pooled)
			encoder.buf.Reset()
			err := encoder.enc.Encode(handlerResponse)
			_, err2 := w.Write(encoder.buf.Bytes())
			encoderPool.Put(encoder)
			if cmp.Or(err, err2) != nil {
				http.Error(w, cmp.Or(err, err2).Error(), http.StatusInternalServerError)
				return
			}
			return
		} else if rtype == apptype.TEXT {
			// If the route type is TEXT, then return the handler response as text
			respHeader["Content-Type"] = CONTENT_TYPE_TEXT
			_, err := fmt.Fprint(w, handlerResponse)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			return
		}

		requestData.Data = handlerResponse
		var err error
		if isHtmxRequest && fragment != "" {
			a.Trace().Msgf("Rendering block %s", fragment)
			err = a.executeTemplate(w, fullHtml, fragment, requestData)
		} else {
			referrer := types.GetHTTPHeader(header, "Referer")
			isUpdateRequest := r.Method != http.MethodGet && r.Method != http.MethodHead && r.Method != http.MethodOptions
			if !isHtmxRequest && isUpdateRequest && fragment != "" && referrer != "" {
				// If block is defined, and this is a non-GET request, then redirect to the referrer page
				// This handles the Post/Redirect/Get pattern required if HTMX is disabled
				a.Trace().Msgf("Redirecting to %s with code %d", referrer, http.StatusSeeOther)
				http.Redirect(w, r, referrer, http.StatusSeeOther)
				return
			} else {
				a.Trace().Msgf("Rendering page %s", fullHtml)
				err = a.executeTemplate(w, fullHtml, "", requestData)
			}
		}

		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	return goHandler
}

func (a *App) handleResponse(retStruct *starlarkstruct.Struct, r *http.Request, w http.ResponseWriter, requestData starlark_type.Request, rtype string, deferredCleanup func() error) (bool, error) {
	// Handle ace.redirect type struct returned by handler
	url, err := apptype.GetStringAttr(retStruct, "url")
	// starlark Type() is not implemented for structs, so we can't check the type
	// Looked at the mandatory properties to decide on type for now
	if err == nil {
		// Redirect type struct returned by handler
		code, err1 := apptype.GetIntAttr(retStruct, "code")
		refresh, err2 := apptype.GetBoolAttr(retStruct, "refresh")
		if err1 != nil || err2 != nil {
			http.Error(w, "Invalid redirect response", http.StatusInternalServerError)
		}

		if refresh {
			w.Header().Add("HX-Refresh", "true")
		}
		a.Trace().Msgf("Redirecting to %s with code %d", url, code)
		if deferredCleanup != nil {
			if err := deferredCleanup(); err != nil {
				return false, err
			}
		}
		http.Redirect(w, r, url, int(code))
		return true, nil
	}

	// Handle ace.response type struct returned by handler
	templateBlock, err := apptype.GetStringAttr(retStruct, "block")
	if err != nil {
		return false, err
	}

	data, err := retStruct.Attr("data")
	if err != nil {
		a.Error().Err(err).Msg("error getting data from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	responseRtype, err := apptype.GetStringAttr(retStruct, "type")
	if err != nil {
		a.Error().Err(err).Msg("error getting type from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}
	if responseRtype == "" {
		// Default to the type set at the route level
		responseRtype = rtype
	}
	responseRtype = strings.ToUpper(responseRtype)
	if templateBlock == "" && responseRtype == apptype.HTML_TYPE {
		return false, fmt.Errorf("block not defined in response and type is not json/text")
	}

	code, err := apptype.GetIntAttr(retStruct, "code")
	if err != nil {
		a.Error().Err(err).Msg("error getting code from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	retarget, err := apptype.GetStringAttr(retStruct, "retarget")
	if err != nil {
		a.Error().Err(err).Msg("error getting retarget from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	reswap, err := apptype.GetStringAttr(retStruct, "reswap")
	if err != nil {
		a.Error().Err(err).Msg("error getting reswap from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	redirect, err := apptype.GetStringAttr(retStruct, "redirect")
	if err != nil {
		a.Error().Err(err).Msg("error getting redirect from response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	templateValue, err := starlark_type.UnmarshalStarlark(data)
	if err != nil {
		a.Error().Err(err).Msg("error converting response")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}

	if strings.ToUpper(responseRtype) == apptype.JSON {
		if deferredCleanup != nil && deferredCleanup() != nil {
			return true, nil
		}
		// If the route type is JSON, then return the handler response as JSON
		w.Header().Set("Content-Type", "application/json")
		err := json.NewEncoder(w).Encode(templateValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true, nil
		}
		return true, nil
	} else if strings.ToUpper(responseRtype) == apptype.TEXT {
		if deferredCleanup != nil && deferredCleanup() != nil {
			return true, nil
		}
		// If the route type is TEXT, then return the handler response as plain text
		w.Header().Set("Content-Type", "text/plain")
		_, err := fmt.Fprint(w, templateValue)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return true, nil
		}
		return true, nil
	}

	requestData.Data = templateValue
	if retarget != "" {
		w.Header().Add("HX-Retarget", retarget)
	}
	if reswap != "" {
		w.Header().Add("HX-Reswap", reswap)
	}
	if redirect != "" {
		w.Header().Add("HX-Redirect", redirect)
	}

	if deferredCleanup != nil && deferredCleanup() != nil {
		return true, nil
	}
	w.WriteHeader(int(code))
	err = a.executeTemplate(w, "", templateBlock, requestData)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return true, nil
	}
	return true, nil
}

func getRemoteIP(r *http.Request) string {
	header := r.Header
	remoteIP := types.GetHTTPHeader(header, REAL_IP_HEADER)
	if remoteIP == "" {
		remoteIP = types.GetHTTPHeader(header, FORWARDED_HEADER)
	}

	if remoteIP != "" {
		return remoteIP
	}

	if r.RemoteAddr != "" {
		var ok bool
		remoteIP, _, ok = strings.Cut(r.RemoteAddr, "]")
		if ok {
			// IPv6
			remoteIP = remoteIP[1:]
		} else {
			remoteIP, _, _ = strings.Cut(r.RemoteAddr, ":")
		}
	}
	return remoteIP
}

func (a *App) handleStreamResponse(w http.ResponseWriter, r *http.Request, rtype string, fragment string, streamResponse map[string]any) {
	// Stream the response to the client
	if rtype == apptype.JSON { //nolint:staticcheck
		w.Header().Set("Content-Type", "application/json")
	} else if rtype == apptype.TEXT {
		w.Header().Set("Content-Type", "text/plain")
	} else {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
	}

	retValue := streamResponse["value"]
	if retValue == nil {
		http.Error(w, "stream value is nil", http.StatusInternalServerError)
		return
	}

	retSeq, ok := retValue.(func(yield func(any, error) bool))
	if !ok {
		http.Error(w, "stream value is not a sequence function", http.StatusInternalServerError)
		return
	}

	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "response writer does not support flushing", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)
	for v := range retSeq {
		if rtype == apptype.TEXT || (rtype == apptype.HTML_TYPE && (fragment == "" || fragment == "-")) {
			vStr, ok := v.(string)
			if !ok {
				vStr = fmt.Sprintf("%v", v)
			}
			vStr = types.StripQuotes(vStr)
			_, err := fmt.Fprint(w, vStr)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if rtype == apptype.HTML_TYPE {
			err := a.executeTemplate(w, "", fragment, v)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		} else if rtype == apptype.JSON {
			err := json.NewEncoder(w).Encode(v)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
		}

		_, err := fmt.Fprint(w, "\n")
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		flusher.Flush()
	}

	if rtype == apptype.HTML_TYPE {
		w.Write([]byte("<!--cl_stream_end-->\n\n")) //nolint:errcheck
		flusher.Flush()
	}
}
