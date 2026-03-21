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

OpenRun is built to be a platform for building internal tools. OpenRun is built in Go and uses [Starlark](https://starlark-lang.org/) for app configuration and also for API business logic. Starlark does not support exceptions and does not support multi-value returns. This makes error handling difficult. The solution implemented for OpenRun is an API boundary error checker with the following properties:

- Automatic error handling, no explicit error checks required for every API call
- Easy way to do explicit error checks when errors are expected

This gives the best of both worlds. All error conditions are automatically checked like exceptions. When explicit error checks are required, they are easy to do like error values.

## How does this work?

The [automatic error handling](https://openrun.dev/docs/plugins/overview/#automatic-error-handling) feature of OpenRun keeps track of every plugin call's status. If the plugin call fails, the OpenRun runtime makes sure that return value cannot be accessed, unless an explicit error check was done. If no explicit check is done, the OpenRun runtime will fail the API, calling the user-defined error handler or a generic error handler if none is defined. So for the code

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

Thread-local storage is used to track errors across plugin API calls. This works since an API handler Starlark function is single-threaded. When begin() fails, it sets a thread-local value. If the error is explicitly checked, like

```
ret = store.begin()
if ret.error:
   pass
print(ret.value)
```

then the thread-local state is cleared. So if the code is doing explicit error checks, the automatic error handling is disabled.

## Can this be a generic solution?

The OpenRun runtime provides all the APIs used by OpenRun apps by means of plugin calls. This solution can be applied when

- All code that can cause errors is provided through a standard API interface
- Thread-local storage is feasible for tracking errors
- There is a standard error handling function which does something useful (could be user defined)

The error check happens at the API boundary (Starlark to Go in this case). If there is code which does excessive CPU usage or memory allocation, that code will run before the automatic error check kicks in. That should not be an issue in practice for glue code as used by OpenRun.

This error handling solution is limited in scope to use cases where glue scripts are being written which make lots of API calls. This provides a shell errexit-type feature for regular code. This does not support error handling that needs to happen within user-defined code, like one function which returns an error to be handled by another function.

Handling resource leaks is another concern. For OpenRun, since all resources (transactions, result sets etc) are created through the plugin API, they are automatically closed when an error occurs.
