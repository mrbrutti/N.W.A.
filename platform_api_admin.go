package main

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
)

func (app *application) handleAdminOverviewJSON(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}

	health, err := app.platform.store.healthSummary()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	engagements, err := app.platform.engagementViewsForUser(user)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	workers, err := app.platform.store.listWorkers()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	tools, err := app.platform.store.listTools()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	audit, err := app.platform.store.recentAudit(0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}

	writeJSON(writer, http.StatusOK, PlatformAdminOverviewAPI{
		Health:      health,
		Engagements: paginateAPIItems(request, engagements),
		Workers:     paginateAPIItems(request, workers),
		Tools:       paginateAPIItems(request, tools),
		Audit:       paginateAPIItems(request, audit),
	})
}

func (app *application) handlePlatformHealthJSON(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	health, err := app.platform.store.healthSummary()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, health)
}

func (app *application) handleAdminUsersJSON(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	users, err := app.platform.store.listUsers()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	items := make([]PlatformUserView, 0, len(users))
	for _, user := range users {
		items = append(items, platformUserView(user))
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleAdminEngagementsJSON(writer http.ResponseWriter, request *http.Request) {
	user, _, ok := app.requirePlatformUser(writer, request, true)
	if !ok {
		return
	}
	engagements, err := app.platform.engagementViewsForUser(user)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, engagements))
}

func (app *application) handleAdminWorkersJSON(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	items, err := app.platform.store.listWorkers()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleAdminConnectorsJSON(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	items, err := app.platform.store.listConnectors()
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleAdminAuditJSON(writer http.ResponseWriter, request *http.Request) {
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	items, err := app.platform.store.recentAudit(0)
	if err != nil {
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	writeJSON(writer, http.StatusOK, paginateAPIItems(request, items))
}

func (app *application) handleAdminToolsJSON(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	switch request.Method {
	case http.MethodGet:
		tools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		if source := strings.TrimSpace(request.URL.Query().Get("source")); source != "" {
			filtered := make([]PlatformToolView, 0, len(tools))
			for _, tool := range tools {
				if tool.InstallSource == source {
					filtered = append(filtered, tool)
				}
			}
			tools = filtered
		}
		writeJSON(writer, http.StatusOK, paginateAPIItems(request, tools))
	case http.MethodPost:
		defer request.Body.Close()
		var payload toolInstallRequest
		if err := json.NewDecoder(request.Body).Decode(&payload); err != nil {
			http.Error(writer, "invalid JSON payload", http.StatusBadRequest)
			return
		}
		definition, err := normalizeInstalledToolRequest(payload)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
			return
		}

		tools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		existingByID := map[string]PlatformToolView{}
		for _, tool := range tools {
			existingByID[tool.ID] = tool
		}
		existing, exists := existingByID[definition.ID]
		if exists && existing.InstallSource != toolInstallSourceCustom {
			http.Error(writer, "cannot overwrite a built-in tool definition", http.StatusBadRequest)
			return
		}

		if err := app.platform.store.upsertToolDefinition(definition, nil); err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		availability := resolveDefinitionAvailability(definition, nil)
		if err := app.platform.store.upsertToolInstallation(definition.ID, availability.Label, chooseString(availability.Reason, definition.Description)); err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}

		updatedTools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for _, tool := range updatedTools {
			if tool.ID != definition.ID {
				continue
			}
			status := http.StatusOK
			if !exists {
				status = http.StatusCreated
			}
			writeJSON(writer, status, tool)
			return
		}
		http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}

func (app *application) handleAdminToolJSON(writer http.ResponseWriter, request *http.Request) {
	if app.platform == nil {
		http.NotFound(writer, request)
		return
	}
	if _, _, ok := app.requirePlatformUser(writer, request, true); !ok {
		return
	}
	toolID := strings.TrimSpace(request.PathValue("toolID"))
	if toolID == "" {
		http.NotFound(writer, request)
		return
	}

	switch request.Method {
	case http.MethodGet:
		tools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for _, tool := range tools {
			if tool.ID == toolID {
				writeJSON(writer, http.StatusOK, tool)
				return
			}
		}
		http.NotFound(writer, request)
	case http.MethodDelete:
		tools, err := app.platform.store.listTools()
		if err != nil {
			http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
			return
		}
		for _, tool := range tools {
			if tool.ID != toolID {
				continue
			}
			if tool.InstallSource != toolInstallSourceCustom {
				http.Error(writer, "only custom tools can be deleted", http.StatusBadRequest)
				return
			}
			if err := app.platform.store.deleteCustomTool(toolID); err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.NotFound(writer, request)
					return
				}
				http.Error(writer, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
				return
			}
			writer.WriteHeader(http.StatusNoContent)
			return
		}
		http.NotFound(writer, request)
	default:
		http.Error(writer, http.StatusText(http.StatusMethodNotAllowed), http.StatusMethodNotAllowed)
	}
}
