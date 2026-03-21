---
title: "Routing"
weight: 200
summary: "Defining API routes, handling pages and fragments"
---

The request routing layer in OpenRun is built on top of the [chi](https://github.com/go-chi/chi) routing library. API requests (JSON or text), HTML requests and proxied requests are supported. For HTML requests, the routing is built for hypermedia exchange, so all routes are defined in terms of pages and fragments within the pages. This grouping of requests helps make it clear which API does what and provide an easy mechanism to deal with partial HTMX driven requests and full page refreshes. Simpler application might have one page with some interactions within that. Larger applications can be composed of multiple pages, each page having some interactive fragments.

## Routes

The app contains an `routes` array, which defines all the routes for the app. For example, the app definition

```python {filename="app.star"}
app = ace.app("hello1",
              routes = [
                 ace.html("/"),
                 ace.html("/help", "help.go.html")
              ]
             )
```

defines two routes. `/` routes to the default index page, `/help` routes to the help page. Routes can be of three types: HTML, API and Proxy.

## HTML Route

An HTML route defined using `ace.html` defines the properties for a HTML page. The response is HTML text. The data returned by the handler function is passed to the template. If the handler returns a `ace.response` or `ace.redirect`, then that takes effect, otherwise the template is rendered.

An HTML route can have fragments defined within it. These are sub-apis which used for hypermedia driven interactions from the main page.

The parameters for `ace.html` are:

| Property  | Optional |      Type      |                        Default                         |                                Notes                                 |
| :-------: | :------: | :------------: | :----------------------------------------------------: | :------------------------------------------------------------------: |
|   path    |  False   |     string     |                                                        |                   The route, should start with a /                   |
|   full    |   True   |     string     | index.go.html if custom layout, else index_gen.go.html |              The template to use for full page requests              |
|  partial  |   True   |     string     |                          None                          |            The template to use for partial page requests             |
|  handler  |   True   |    function    |                  handler (if defined)                  |              The handler function to use for the route               |
| fragments |   True   | ace.fragment[] |                           []                           |                          The fragment array                          |
|  method   |   True   |     string     |                          GET                           | The HTTP method type: GET,POST,PUT,DELETE etc, for example `ace.GET` |

## Fragment

The fragments array in the html page definition defines the API interactions within the page. The parameters for `ace.Fragment` are:

| Property | Optional |   Type   |       Default       |                                Notes                                 |
| :------: | :------: | :------: | :-----------------: | :------------------------------------------------------------------: |
|   path   |  False   |  string  |                     |                 The route, should not start with a /                 |
| partial  |   True   |  string  | Inherited from page |               The template to use for partial requests               |
| handler  |   True   | function | Inherited from page |              The handler function to use for the route               |
|  method  |   True   |  string  |         GET         | The HTTP method type: GET,POST,PUT,DELETE etc, for example `ace.GET` |

{{<callout type="info" >}}
`partial` and `handler` are inherited from the page level, unless overridden for the fragment.
{{</callout>}}

For example, in this page definition

```python {filename="app.star"}
ace.html("/game/{game_id}", full="game.go.html", partial="game_info_tmpl", handler=game_handler,
    fragments=[
        ace.fragment(
            "submit", method=ace.POST, handler=lambda req: post_game_update(req, "submit")),
        ace.fragment(
            "refresh", partial="refresh_tmpl")
    ]
)
```

there are three APIs defined:

- GET /game/{game_id} : game_handler is the handler function, full page request returns game.go.html, partial HTMX request returns game_info_tmpl template.
- POST /game/{game_id}/submit : The handler is a lambda function. The game_info_tmpl template partial is inherited from the page as the response for the POST.
- GET /game/{game_id}/refresh : game_handler is inherited from the page. For full page, it returns the game.go.html response. For partial HTMX requests, refresh_tmpl template is returned.

## API Route

An API route defines a route which returns JSON (default) or plain text response. The handler response is converted to the desired format and returned. The parameters for `ace.api` are:

| Property | Optional |   Type   |       Default        |                                Notes                                 |
| :------: | :------: | :------: | :------------------: | :------------------------------------------------------------------: |
|   path   |  False   |  string  |                      |                   The route, should start with a /                   |
| handler  |   True   | function | handler (if defined) |              The handler function to use for the route               |
|  method  |   True   |  string  |         GET          | The HTTP method type: GET,POST,PUT,DELETE etc, for example `ace.GET` |
|   type   |   True   |  string  |         JSON         |             The response type, `ace.JSON` or `ace.TEXT`              |

For example

```python {filename="app.star"}

def handler(req):
    return {"a": 1}

app = ace.app("api",
              routes = [
                 ace.api("/myapi")
              ]
             )
```

A GET request to `/myapi` endpoint will return JSON `{"a": 1}`.

## Proxy Route

A Proxy route defines a route which has to be proxied to another service. All API calls under that route are proxied (all methods and all sub-routes). Websocket connections are also proxied. Proxy uses a plugin based config, the app has to be authorized to do the proxying. The parameters for `ace.Proxy` are:

| Property | Optional |    Type     | Default |              Notes               |
| :------: | :------: | :---------: | :-----: | :------------------------------: |
|   path   |  False   |   string    |         | The route, should start with a / |
|  config  |  False   | ProxyConfig |         |  The proxy configuration to use  |

The proxy configuration `proxy.config` has the options:

|   Property    | Optional |  Type   | Default |                                                  Notes                                                   |
| :-----------: | :------: | :-----: | :-----: | :------------------------------------------------------------------------------------------------------: |
|      url      |  False   | string  |         |                                    The url to forward the requests to                                    |
|  strip_path   |   True   | string  |         | Additional path components to strip from the request path. The app installation path is always stripped. |
| preserve_host |  False   | boolean |         |   Whether to preserve the Host header. Default false, the Host header is set to the target host value    |

For example, an app which forwards requests to `www.google.com` is

```python {filename="app.star"}
load("proxy.in", "proxy")

app = ace.app("Proxy",
              routes=[
                ace.proxy("/", proxy.config("https://www.google.com")),
              ],
              permissions=[
                  ace.permission("proxy.in", "config", ["https://www.google.com"]),
              ],
      )

```

The plugin is authorized to allow proxying to `https://www.google.com`. Any request to the app will be forwarded after stripping the app path. So if app is installed at `/test`, a request to `/test/abc/def` will be forwarded to `/abc/def`. In addition, if the proxy is configured with `strip_path="/abc"`, then the request will be sent to `/def`.

If proxying is enabled for `/` route, then `/static` file serving is disabled for the app since requests to static path are also forwarded to the upstream service. `/static_root` serving is available and overrides the proxy config.

See [proxy plugin]({{< ref "docs/plugins/proxy" >}}) for details about the proxy config.

{{<callout type="warning" >}}
**Note:** If the upstream service uses relative paths, then all requests are automatically proxied. If the service uses absolute paths, then it is better that the app is installed at the root path, like `example.com:` instead of `example.com:/test`. If the service uses absolute paths including the domain name, then the client will see the absolute paths and those requests will not come through the proxy. The HTML body is not rewritten by OpenRun to rewrite path references. The upstream service needs to use relative paths to ensure that all requests come through OpenRun.
{{</callout>}}

## Request Flow

The API flow is

- The API is first sent to the matching app
- Within the app, the API is routed based on the routes defined
- If there is a handler defined for the matched route, the handler function is called with the request as argument
- The response template is invoked, with an input map containing a `Data` property as returned by the handler function
- If the API type is set to JSON, the handler response is directly returned, with no template being used
- If [automatic error handling]({{< ref "docs/plugins/overview#automatic-error-handling" >}}) is enabled (`error_handler` is defined), then the error handler function is called if there is an error during the handler invocation. The error handler does the response processing, the templates defined in the route are not used.

## Notes

- For HTMX requests, the `partial` template is used. For regular requests, the page-level `full` template is used
- If there is a function called `handler` defined, that is the default handler function for all APIs
- For non-HTMX update requests (POST/PUT/DELETE), the [Post-Redirect-Get](https://en.wikipedia.org/wiki/Post/Redirect/Get) pattern is automatically implemented by redirecting to the location pointed to by the `Referer` header.
