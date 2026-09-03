package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// readWebFile reads a file from the web directory relative to the repository
// root, which is two levels up from this package.
func readWebFile(t *testing.T, parts ...string) string {
	t.Helper()
	path := filepath.Join(append([]string{"..", "..", "web"}, parts...)...)
	contents, err := os.ReadFile(path)
	require.NoError(t, err)
	return string(contents)
}

func TestBaseLayoutLoadsTheThemeAssets(t *testing.T) {
	layout := readWebFile(t, "templates", "layouts", "base.html")

	require.Contains(t, layout, "/static/dark-mode.css")
	require.Contains(t, layout, "/static/theme-toggle.js")
	require.Contains(t, layout, `class="theme-toggle nav-link"`)
}

func TestThemeScriptIsLoadedBeforeTheBody(t *testing.T) {
	layout := readWebFile(t, "templates", "layouts", "base.html")

	// Loading the script in the head is what prevents a flash of the wrong
	// theme before the stored preference is applied.
	scriptIndex := strings.Index(layout, "/static/theme-toggle.js")
	bodyIndex := strings.Index(layout, "<body>")
	require.Positive(t, scriptIndex)
	require.Positive(t, bodyIndex)
	require.Less(t, scriptIndex, bodyIndex)
}

func TestThemeToggleIsBoundOnceOnly(t *testing.T) {
	layout := readWebFile(t, "templates", "layouts", "base.html")
	script := readWebFile(t, "static", "theme-toggle.js")

	// The script binds its own click listener, so an inline onclick would
	// advance the theme twice per click.
	require.Contains(t, script, "addEventListener('click', toggleTheme)")
	require.NotContains(t, layout, "onclick=\"toggleTheme()\"")
}

func TestDarkThemeDefinesEveryTokenItOverrides(t *testing.T) {
	stylesheet := readWebFile(t, "static", "dark-mode.css")

	// Every custom property the dark theme sets must also exist in the light
	// default, or a viewer in one theme inherits a colour from the other.
	light := customProperties(stylesheet, ":root {")
	dark := customProperties(stylesheet, `[data-theme="dark"] {`)
	require.NotEmpty(t, light)
	require.NotEmpty(t, dark)
	for name := range dark {
		require.Contains(t, light, name, "dark theme defines %s with no light default", name)
	}
}

// customProperties extracts the custom property names declared in the first
// block opened by the given selector.
func customProperties(stylesheet, selector string) map[string]bool {
	start := strings.Index(stylesheet, selector)
	if start < 0 {
		return nil
	}
	block := stylesheet[start+len(selector):]
	if end := strings.Index(block, "}"); end >= 0 {
		block = block[:end]
	}
	names := map[string]bool{}
	for _, line := range strings.Split(block, "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "--") {
			continue
		}
		if colon := strings.Index(trimmed, ":"); colon > 0 {
			names[strings.TrimSpace(trimmed[:colon])] = true
		}
	}
	return names
}
