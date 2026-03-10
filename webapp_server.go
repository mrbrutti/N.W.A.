package main

import (
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"strings"
)

func (app *application) handleReactApp(writer http.ResponseWriter, request *http.Request) {
	distRoot := filepath.Join("webapp", "dist")
	indexPath := filepath.Join(distRoot, "index.html")
	if _, err := os.Stat(indexPath); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			http.Error(writer, "React app is not built. Run `npm --prefix webapp install && npm --prefix webapp run build` or `npm --prefix webapp run dev`.", http.StatusServiceUnavailable)
			return
		}
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	trimmed := strings.TrimPrefix(request.URL.Path, "/app")
	trimmed = strings.TrimPrefix(trimmed, "/")
	if trimmed != "" && strings.Contains(filepath.Base(trimmed), ".") {
		targetPath := filepath.Join(distRoot, filepath.FromSlash(trimmed))
		if _, err := os.Stat(targetPath); err == nil {
			http.ServeFile(writer, request, targetPath)
			return
		}
	}
	http.ServeFile(writer, request, indexPath)
}

func (app *application) handleAdminReactRedirect(writer http.ResponseWriter, request *http.Request) {
	target := "/app" + request.URL.Path
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	http.Redirect(writer, request, target, http.StatusSeeOther)
}

func (app *application) handleEngagementReactRedirect(writer http.ResponseWriter, request *http.Request) {
	target := "/app" + request.URL.Path
	if request.URL.RawQuery != "" {
		target += "?" + request.URL.RawQuery
	}
	http.Redirect(writer, request, target, http.StatusSeeOther)
}
