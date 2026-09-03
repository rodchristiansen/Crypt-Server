package app

import (
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRouterMatchesLiteralAndWildcardSegments(t *testing.T) {
	router := newAPIRouter("/api/v1")
	router.handle(http.MethodGet, "computers/{id}/secrets", func(http.ResponseWriter, *http.Request, pathValues) {})

	route, values, ok, pathMatched := router.match(http.MethodGet, "/api/v1/computers/42/secrets")

	require.True(t, ok)
	require.True(t, pathMatched)
	require.NotNil(t, route.handler)
	require.Equal(t, "42", values["id"])
}

func TestRouterDistinguishesMissingPathFromWrongMethod(t *testing.T) {
	router := newAPIRouter("/api/v1")
	router.handle(http.MethodGet, "computers", func(http.ResponseWriter, *http.Request, pathValues) {})

	_, _, ok, pathMatched := router.match(http.MethodPost, "/api/v1/computers")
	require.False(t, ok)
	require.True(t, pathMatched)

	_, _, ok, pathMatched = router.match(http.MethodGet, "/api/v1/elsewhere")
	require.False(t, ok)
	require.False(t, pathMatched)
}

func TestRouterDoesNotMatchDifferentSegmentCounts(t *testing.T) {
	router := newAPIRouter("/api/v1")
	router.handle(http.MethodGet, "computers/{id}", func(http.ResponseWriter, *http.Request, pathValues) {})

	_, _, ok, _ := router.match(http.MethodGet, "/api/v1/computers/42/secrets")

	require.False(t, ok)
}

func TestRouterPrefersLiteralOverWildcard(t *testing.T) {
	router := newAPIRouter("/api/v1")
	router.handle(http.MethodGet, "computers/stale", func(http.ResponseWriter, *http.Request, pathValues) {})
	router.handle(http.MethodGet, "computers/{id}", func(http.ResponseWriter, *http.Request, pathValues) {})

	_, values, ok, _ := router.match(http.MethodGet, "/api/v1/computers/stale")

	require.True(t, ok)
	require.NotContains(t, values, "id")
}
