package app

import (
	"net/http"
	"strings"
)

// apiRoute is one entry in the API route table. Pattern segments wrapped in
// braces are wildcards and are captured into the request's path values.
type apiRoute struct {
	method   string
	segments []string
	handler  func(http.ResponseWriter, *http.Request, pathValues)
}

// pathValues holds the wildcard segments captured from a matched route.
type pathValues map[string]string

// apiRouter is a small method-aware router. Go 1.21's ServeMux cannot express
// method or wildcard patterns, and the API is not worth a third-party
// dependency, so routes are matched segment by segment here.
type apiRouter struct {
	prefix string
	routes []apiRoute
}

func newAPIRouter(prefix string) *apiRouter {
	return &apiRouter{prefix: strings.TrimSuffix(prefix, "/")}
}

// handle registers a handler. The pattern is relative to the router prefix,
// for example "computers/{id}/secrets".
func (router *apiRouter) handle(method, pattern string, handler func(http.ResponseWriter, *http.Request, pathValues)) {
	router.routes = append(router.routes, apiRoute{
		method:   method,
		segments: splitPath(pattern),
		handler:  handler,
	})
}

func splitPath(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return []string{}
	}
	return strings.Split(trimmed, "/")
}

// match finds the handler for a request path. It reports whether any route
// matched the path regardless of method, so the router can answer 405 rather
// than 404 when only the verb is wrong.
func (router *apiRouter) match(method, path string) (apiRoute, pathValues, bool, bool) {
	requested := splitPath(strings.TrimPrefix(path, router.prefix))
	pathMatched := false
	for _, route := range router.routes {
		values, ok := matchSegments(route.segments, requested)
		if !ok {
			continue
		}
		pathMatched = true
		if route.method == method {
			return route, values, true, true
		}
	}
	return apiRoute{}, nil, false, pathMatched
}

func matchSegments(pattern, requested []string) (pathValues, bool) {
	if len(pattern) != len(requested) {
		return nil, false
	}
	values := pathValues{}
	for index, segment := range pattern {
		if strings.HasPrefix(segment, "{") && strings.HasSuffix(segment, "}") {
			name := strings.TrimSuffix(strings.TrimPrefix(segment, "{"), "}")
			if requested[index] == "" {
				return nil, false
			}
			values[name] = requested[index]
			continue
		}
		if segment != requested[index] {
			return nil, false
		}
	}
	return values, true
}

// ServeHTTP dispatches a request against the route table.
func (router *apiRouter) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	route, values, ok, pathMatched := router.match(r.Method, r.URL.Path)
	if !ok {
		if pathMatched {
			writeAPIError(w, http.StatusMethodNotAllowed, "method_not_allowed", "That method is not supported on this endpoint.", nil)
			return
		}
		writeAPIError(w, http.StatusNotFound, "not_found", "No such endpoint.", nil)
		return
	}
	route.handler(w, r, values)
}
