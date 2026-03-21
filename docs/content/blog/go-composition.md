---
title: "Go Composition does not work well with Implicit Interfaces"
summary: "Go supports composition as against inheritance for extending behavior. Composition can break code which uses implicit interfaces."
date: 2024-12-24
---

{{< openrun-intro >}}

## Background

I recently encountered an issue where Server-Sent Events (SSE) stopped working in OpenRun. SSE are used for live reload functionality in OpenRun. The problem turned out to be a recent change in OpenRun which added support for tracking HTTP response status code. This was implemented by composing over the `http.ResponseWriter` to keep track of the status code. This composition broke the SSE functionality.

## Composition over Inheritance

Go supports [embedding](https://go.dev/doc/effective_go#embedding), which can be used to implement Composition (has-a relationship) rather than inheritance (is-a relationship). Composition has some [benefits](https://en.wikipedia.org/wiki/Composition_over_inheritance#Benefits) over inheritance. Embedding in Go allows the use of composition without requiring forwarding methods.

## Implicit Interfaces

Interfaces in Go are implemented [implicitly](https://go.dev/tour/methods/10). This is a powerful feature, allowing interfaces to be added when required later. Interfaces can even be created for types in different packages. This allows clients to control how types are used rather than depending on how the types were originally defined.

## Stdlib Implicit Interfaces

The Go stdlib uses implicit interfaces to implement optimizations (like [io.WriterTo](https://pkg.go.dev/io#WriterTo) and [io.ReaderFrom](https://pkg.go.dev/io#ReaderFrom)) and custom behaviors (like [fmt.Stringer](https://pkg.go.dev/fmt#Stringer)). Other similar interfaces are http.Hijacker, http.Pusher, and io.Closer.

## Composition breaks Implicit Interfaces

The reason for the issue encountered is an implicit interface [http.Flusher](https://pkg.go.dev/net/http#Flusher) implemented by most implementations of [http.ResponseWriter](https://pkg.go.dev/net/http#ResponseWriter). Adding a composition over `http.ResponseWriter` causes this implicit interface to no longer be implemented.

```go
type CustomWriter struct {
	http.ResponseWriter
	statusCode int
}
```

Here, `CustomWriter` no longer implements `http.Flusher`, even if the underlying `http.ResponseWriter` implementation did. SSE was supported for flushable writers only, so adding the composition broke SSE. The fix is to have the composing struct explicitly implement `http.Flusher`. See [go playground](https://go.dev/play/p/IQ4qtCzjaTC) to see an example.

## Fixing the issue

```go
func (cw *CustomWriter) Flush() {
  if flusher, ok := cw.ResponseWriter.(http.Flusher); ok {
    flusher.Flush()
  }
}
```

Adding a `Flush` function is a fix, but an issue with this is that if the caller had support for non-flushable writers, that behavior is lost. A better fix is to have two implementations, one flushable and another non-flushable. The appropriate one should be used based on whether the underlying writer implements `http.Flusher`. This way, the original behavior is not changed by adding the composition.

```go
type FlushableWriter interface {
	http.ResponseWriter
	http.Flusher
}

type FlushableCustomWriter struct {
	FlushableWriter
	statusCode int
}

type CustomWriter struct {
	http.ResponseWriter
	statusCode int
}
```

Some HTTP routers like [Chi](https://go-chi.io/#/README) have [middleware](https://pkg.go.dev/github.com/go-chi/chi/middleware#NewWrapResponseWriter) which implement the required implicit interfaces.

## How to avoid this issue

The Go type system does not have a way to catch such issues at compile time. At runtime, the issue can show up as a performance degradation (if the implicit interface is used as a performance optimization) or as an unexpected behavior (if custom behavior is implemented using the implicit interface).

It would have helped if the documentation for [http.ResponseWriter](https://pkg.go.dev/net/http#ResponseWriter) had mentioned the `http.Flusher` interface and when it is used. This is feasible when the types are in the same package.

The takeaway is that if using composition over types which could have implicit interfaces, it is important to look at whether any of those implicit interfaces have to be explicitly implemented by the composing type.

{{<callout emoji="💬" >}}
Discussion thread on [Reddit](https://www.reddit.com/r/golang/comments/1hm54r4/go_composition_can_break_implicit_interfaces/)
{{</callout>}}
