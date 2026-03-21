---
title: "Response"
weight: 400
summary: "The response from the handler function, custom response and redirects"
---

## Response Data

The Response from the handler function is passed to the template to be converted to HTML. The handler response is accessible through `.Data`, or `$Data` if in [another scope](https://pkg.go.dev/text/template#:~:text=When%20execution%20begins%2C%20%24%20is%20set%20to%20the%20data%20argument%20passed%20to%20Execute%2C%20that%20is%2C%20to%20the%20starting%20value%20of%20dot.). Any python object can be used as the return value. Using a dictionary is recommended, so that error handling is easier. Adding a `Error` key in the response dict can indicate to the template that an error condition needs to be handled.

For example, a handler like

```python {filename="app.star"}
def handler(req):
    name = req.Query.get("name")

    if name:
        return {"Name": name[0], "Error": None}
    else:
        return {"Error": "Name not specified", "Name": None}

app = ace.app("test", routes = [ace.html("/")])
```

allows the template to handle the error by doing

<!-- prettier-ignore -->
```html
{{block "openrun_body" .}}
{{if .Data.Error}}
    <div style="color: red">{{.Data.Error}}</div>
{{else}}
    Hi {{.Data.Name}}
{{end}}
{{end}}

```

<!-- prettier-ignore-end -->

## Redirect Response

If the API needs to redirect the client to another location after a POST/PUT/DELETE operation, the handler function can return an `ace.Redirect` structure. The fields in this structure are:

| Property | Optional |  Type  | Default |              Notes               |
| :------: | :------: | :----: | :-----: | :------------------------------: |
|   url    |  false   | string |         |      The url to redirect to      |
|   code   |   true   |  int   |   303   | The HTTP status code, 303 or 302 |

For example, this code does a 303 redirect after a POST API, which provides [handling](https://en.wikipedia.org/wiki/Post/Redirect/Get) for update requests.

```python {filename="app.star"}
def create_game(req):
    level = req.Form["level"]
    ret = http.post(SERVICE_URL + "/api/create_game/" + level[0])
    return ace.redirect(req.AppPath + "/game/" + ret.json()["GameId"])
```

## Custom Response

In some cases, a custom response need to be generated, with special headers. Or the response needs to use a template different from the one defined in the route, which could happen in the case of an error. For such cases, a `ace.Response` structure can be returned by the handler. The fields in this structure are:

| Property | Optional |  Type  |                 Default                  |                                                                                Notes                                                                                 |
| :------: | :------: | :----: | :--------------------------------------: | :------------------------------------------------------------------------------------------------------------------------------------------------------------------: |
|   data   |  false   | object |                                          |                                                                          The response data                                                                           |
|  block   |   true   | string |                                          |                                                                   Optional only if type is "json"                                                                    |
|   type   |   true   | string | inherited from the route type definition |                                                                     If "json", block is ignored                                                                      |
|   code   |   true   |  int   |                   200                    |                                                                           HTTP status code                                                                           |
| retarget |   true   | string |                                          | [HX-Retarget](https://htmx.org/reference/#:~:text=for%20possible%20values-,HX%2DRetarget,-a%20CSS%20selector) header value, CSS selector to target, like "#error_id" |
|  reswap  |   true   | string |                                          |                       [HX-Reswap](https://htmx.org/reference/#:~:text=the%20location%20bar-,HX%2DReswap,-allows%20you%20to), like "outerHTML"                        |

For example, this handler code uses retarget to handle errors by updating the html property which has id "gameErrorId"

```python {filename="app.star"}
ret = http.post(api_url).json()
if ret.get("Error"):
    return ace.response(ret, "game_error_block", retarget="#gameErrorId")
return fetch_game(req, game_id)
```

This code returns a 404 with a custom body generated from a template block called "invalid_challenge_block"

```python {filename="app.star"}
if challenge.get("Error"):
    return ace.response(challenge, "invalid_challenge_block", code=404)
```

## JSON Response

All responses are HTML by default, as required for building a proper Hypermedia client. There are some cases where data needs to be returned to the client in JSON format. The type property can be used for those cases. For example, [this API](https://github.com/openrundev/apps/blob/dbec99126329adbcff30824b050ff1d559922bdd/system/memory_usage/app.star#L98) returns JSON

```python {filename="app.star"}
ace.api("/memory", handler=memory_handler),
```

Here, the response from the handler function is returned as JSON, no template is used. Also, in this handler, if there is a call to `ace.Response`, the type will default to JSON since that is the type specified at the route level. Mime type detection based on the `Accept` header is planned, it is not currently supported.
