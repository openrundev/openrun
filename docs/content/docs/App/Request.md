---
title: "Request"
weight: 300
summary: "The Request structure passed into the handler function, handling argument and post data"
---

## Request Structure

The handler function is passed one argument which has the details about the API call. The fields in this structure are:

| Property  |  Type  |                              Notes                              |
| :-------: | :----: | :-------------------------------------------------------------: |
|  AppName  | string |                   The app name in the config                    |
|  AppPath  | string | The path where the app is installed. If root, then empty string |
|  AppUrl   | string |                    The url for the app root                     |
| PagePath  | string |    The path for the current page. If root, then empty string    |
|  PageUrl  | string |                  The url for the current page                   |
|  Method   | string |                  The HTTP method, GET/POST etc                  |
|   IsDev   |  bool  |                Is the app installed in dev mode                 |
| IsPartial |  bool  |             Is this an HTMX driven partial request              |
| RemoteIP  | string |                      The Client IP address                      |
| UrlParams |  dict  |           The url parameters, if used in the url spec           |
|   Form    |  dict  |             The form data, including body and query             |
|   Query   |  dict  |              The url query data, as a string array              |
| PostForm  |  dict  |                   The form data from the body                   |
|   Data    |  dict  | The response from the handler function (passed to the template) |

## Accessing Inputs

### Url Parameters

For a route defined like

```python {filename="app.star"}
ace.html("/user/{user_id}/settings", "index.go.html")
```

the url parameter `user_id` can be accessed in the handler

```python {filename="app.star"}
def handler(req)
    user_id = req.UrlParams["user_id"]
```

[Wildcard parameters](https://go-chi.io/#/pages/routing?id=routing-patterns-amp-url-parameters) are allowed at the end of the route. These are defined as

```python {filename="app.star"}
ace.html("/path/*", "index.go.html")
```

and can be accessed as

```python {filename="app.star"}
def handler(req)
    user_id = req.UrlParams["*"]
```

[Regexes](https://github.com/google/re2/wiki/Syntax) are also allowed in the path, these are defined as `ace.html("/articles/{aid:^[0-9]{5,6}}")` and accessed as `req.UrlParams["{aid}"]`. The route will match only if the regex matches.

### Query String Parameters

Query string parameters can be accessed as

```python {filename="app.star"}
def handler(req)
    name = req.Query.get("name")
    name = name[0] if name else None
```

The value for Query is an string array, since there can be multiple query parameters with the same name.

### Form Data

Form data can be accessed like

```python {filename="app.star"}
def handler(req)
    name = req.Form.get("name")
    name = name[0] if name else None
```

The value for Form is an string array, since there can be multiple form parameters with the same name.
