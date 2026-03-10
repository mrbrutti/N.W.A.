package main

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"
)

type platformSessionPayload struct {
	Authenticated bool                     `json:"authenticated"`
	User          *PlatformUserView        `json:"user,omitempty"`
	Engagements   []PlatformEngagementView `json:"engagements,omitempty"`
	RedirectTo    string                   `json:"redirectTo,omitempty"`
	BootstrapHint string                   `json:"bootstrapHint,omitempty"`
}

type platformLoginPayload struct {
	Login    string `json:"login"`
	Password string `json:"password"`
}

func (app *application) handleSessionJSON(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	user, _, err := app.platform.userFromRequest(request)
	if err != nil {
		writeJSON(writer, http.StatusOK, platformSessionPayload{
			Authenticated: false,
			BootstrapHint: app.platform.bootstrapHint,
		})
		return
	}
	engagements, _ := app.platform.engagementViewsForUser(user)
	writeJSON(writer, http.StatusOK, app.sessionPayload(user, engagements))
}

func (app *application) handleSessionLoginJSON(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}

	payload := platformLoginPayload{}
	if strings.Contains(request.Header.Get("Content-Type"), "application/json") {
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
	} else {
		if err := request.ParseForm(); err != nil {
			http.Error(writer, http.StatusText(http.StatusBadRequest), http.StatusBadRequest)
			return
		}
		payload.Login = request.FormValue("login")
		payload.Password = request.FormValue("password")
	}

	user, token, err := app.platform.authenticate(strings.TrimSpace(payload.Login), payload.Password, request)
	if err != nil {
		writeJSON(writer, http.StatusUnauthorized, map[string]string{"error": "invalid credentials"})
		return
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     platformSessionCookie,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Now().Add(7 * 24 * time.Hour),
	})
	engagements, _ := app.platform.engagementViewsForUser(user)
	writeJSON(writer, http.StatusOK, app.sessionPayload(user, engagements))
}

func (app *application) handleSessionLogoutJSON(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if request.Method != http.MethodPost {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	if user, token, err := app.platform.userFromRequest(request); err == nil {
		app.platform.logout(token, user)
	}
	http.SetCookie(writer, &http.Cookie{
		Name:     platformSessionCookie,
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
		Expires:  time.Unix(0, 0),
		MaxAge:   -1,
	})
	writeJSON(writer, http.StatusOK, platformSessionPayload{Authenticated: false})
}

func (app *application) handleEngagementsJSON(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, false)
	if !ok {
		return
	}
	if request.Method != http.MethodGet {
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
		return
	}
	items, err := app.platform.engagementViewsForUser(user)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, items)
}

func (app *application) sessionPayload(user platformUserRecord, engagements []PlatformEngagementView) platformSessionPayload {
	redirectTo := "/app/engagements"
	if user.IsAdmin {
		redirectTo = "/app/admin"
	}
	userView := platformUserView(user)
	return platformSessionPayload{
		Authenticated: true,
		User:          &userView,
		Engagements:   engagements,
		RedirectTo:    redirectTo,
	}
}
