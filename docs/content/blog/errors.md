---
title: "Errors and Exceptions: Is there a third option?"
summary: "Error handling for glue code, how to avoid verbosity while allowing custom error handling."
date: 2024-12-09
---

{{< openrun-intro >}}

## Background

Most programming languages handle error conditions either by supporting error values or by means of exceptions. Error return value support varies, with some statically typed languages enforcing that the error conditions be handled. With exceptions, the invoker can either catch and handle it or it automatically gets thrown up the stack. The purpose of error handling is to allow an invoker to either handle the issue or allow the invoker to return the error to the caller.

Exceptions have the advantage of the error handling being automatic. Error values have the advantage of requiring more explicit error handling, at the cost of verbosity.

## Error handling for Glue code

For code which is gluing together multiple APIs, error handling can be tedious. Some languages have specific support for this. The most famous example is the [errexit](https://www.baeldung.com/linux/bash-script-raise-error) setting `set -e` in shell scripts. This will automatically check each command for error return status and fail the script if an error occurs.

## Trade-Offs

The two main trade-offs we are handling are:

- Exceptions are automatically checked, but they result in error handling being done away from the code which actually failed.
- Error values need to be checked explicitly, but the error handling code is local to where the error occurred. In most languages, it is easy to miss checking for errors (Rust being one exception with the Result type)

The ideal scenario in terms of code verbosity is that error handling should be automatic. The ideal scenario in terms of proper error handling is that the explicit error checks should be easy for the invoker, else the automatic error handling kicks in.

## Is there a third option?

OpenRun is built to be a platform for building internal tools. OpenRun is built in Go and uses [Starlark](https://starlark-lang.org/) for app configuration and also for API business logic. Starlark does not support exceptions: a runtime failure aborts the whole execution and there is no way to catch it. A function can return a tuple, so Go-style `value, err` returns are possible, but that brings back the verbosity and nothing forces the caller to look at the error. This makes error handling difficult. The solution implemented for OpenRun is an API boundary error checker with the following properties:

- Automatic error handling, no explicit error checks required for every API call
- Easy way to do explicit error checks when errors are expected

This gives the best of both worlds. All error conditions are automatically checked like exceptions. When explicit error checks are required, they are easy to do like error values.

## How does this work?

The [automatic error handling](https://openrun.dev/docs/plugins/overview/#automatic-error-handling) feature of OpenRun keeps track of every plugin call's status. If the plugin call fails, the OpenRun runtime makes sure that the return value cannot be accessed: reading the `value` of a failed call always aborts the handler. The runtime also makes sure that the failure cannot be silently ignored. If no explicit check is done, the OpenRun runtime will fail the API, calling the user-defined error handler or a generic error handler if none is defined. So for the code

```
    def insert(req):
        store.begin()
        book = doc.bookmark("abc", [])
        ret = store.insert(table.bookmark, book)
        print(ret.value)
        store.commit()
```

- If begin() fails, the call to insert() will fail since the previous error was not handled (begin's error message is raised).
- If insert() fails, the value access will fail, so the print will not run
- If commit() fails, the OpenRun runtime will first check whether the last plugin failed before handling the API response.

So an unchecked failure is caught at one of three points: when the value is accessed, when the next plugin call is made, or when the handler returns. In all three cases the handler's own response is discarded and the error handler's response is returned instead.

Thread-local storage is used to track errors across plugin API calls. This works since an API handler Starlark function is single-threaded. When begin() fails, it sets a thread-local value. If the error is explicitly checked, like

```
ret = store.begin()
if ret.error:
    return ace.response(ret, "error.go.html")
print(ret.value)
```

then the thread-local state is cleared. Checking the truth value, as in `if not ret:`, does the same. So if the code is doing explicit error checks, the automatic error handling is disabled for that call. The handler then owns the error: it can return a custom response as above, or it can deliberately ignore the failure and continue. Ignoring an error is possible, but it has to be written out in the code, it cannot happen by omission. Even after an explicit check, the `value` of a failed call cannot be read.

## Related approaches

The individual ideas used here are not new. Similar approaches in other languages and runtimes include:

- Raku has a [Failure](https://docs.raku.org/type/Failure) type, which is the closest match. A function returns a `Failure` instead of throwing. Checking whether it is true or defined marks it as handled. Using it as a regular value throws the exception.
- LLVM has the [Error and Expected](https://llvm.org/docs/ProgrammersManual.html#recoverable-errors) types for C++. An error has to be checked before it is destroyed, otherwise the program aborts in builds which have the check enabled. Converting the error to a boolean is what marks it as checked.
- Rust's `Result::unwrap()` and C++'s `std::expected::value()` fail when the value of an error result is accessed. This is the same as the value access check, but it does not catch a result which is never looked at. Rust handles that case at compile time with `#[must_use]`.
- Node.js fails the process on an unhandled promise rejection and Python's asyncio logs a task exception which was never retrieved. The runtime tracks whether an error was observed, but the detection happens late, at garbage collection or at the end of the event loop tick.
- Shell `set -e` and Perl's `autodie` fail at the call itself. Handling an expected error requires opting out of the automatic check for that call.

What is different in the OpenRun approach is where the check is enforced. Destructors and garbage collection run at times which are hard to predict, and some languages do not have them. OpenRun does the check at the API boundary: at the next plugin call and when the handler returns. Since the Starlark code cannot cause side effects without a plugin call, checking at those points is enough to ensure that an unhandled failure stops the handler before it does anything further.

## Can this be a generic solution?

The OpenRun runtime provides all the APIs used by OpenRun apps by means of plugin calls. This solution can be applied when

- All code that can cause errors is provided through a standard API interface
- Thread-local storage is feasible for tracking errors
- There is a standard error handling function which does something useful (could be user defined)

The error check happens at the API boundary (Starlark to Go in this case). If there is code which does excessive CPU usage or memory allocation, that code will run before the automatic error check kicks in. That should not be an issue in practice for glue code as used by OpenRun.

The handler does keep running between the failed call and the next check point. This is safe because Starlark code has no I/O of its own. Every side effect (database write, HTTP call, running a command) goes through a plugin call, and the next plugin call is refused while a failure is pending. The code in between can only compute on local values, and its result is thrown away when the error is raised. A language where user code can cause side effects directly would not have this guarantee.

This error handling solution is limited in scope to use cases where glue scripts are being written which make lots of API calls. This provides a shell errexit-type feature for regular code. The automatic tracking does not cover errors raised within user-defined code, like one function which returns an error to be handled by another function. For that case, OpenRun has an [`ace.output`](https://openrun.dev/docs/plugins/overview/#returning-errors-from-functions) struct with the same value-access rule: reading the `value` of an error output aborts the handler. The next-call and handler-return checks apply only to plugin calls.

Handling resource leaks is another concern. For OpenRun, since all resources (transactions, result sets etc) are created through the plugin API, they are tracked by the runtime and automatically closed when the handler exits, whether it completed or was aborted by an error.
