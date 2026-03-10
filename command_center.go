package main

import (
	"errors"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

const workspaceCookieName = "nwa_workspace"

type applicationConfig struct {
	SeedFiles       []string
	WorkspaceTarget string
	DBDSN           string
	DataDir         string
}

type commandCenter struct {
	logger *slog.Logger

	mu         sync.Mutex
	service    *serviceStore
	dataDir    string
	cache      map[string]*workspace
	bundle     *workspace
	bundleMeta workspaceMetaRecord
}

func newApplication(seedFiles []string, workspaceDir string, logger *slog.Logger) (*application, error) {
	return newApplicationWithConfig(applicationConfig{
		SeedFiles:       seedFiles,
		WorkspaceTarget: workspaceDir,
		DBDSN:           strings.TrimSpace(os.Getenv("NWA_DB_DSN")),
		DataDir:         strings.TrimSpace(os.Getenv("NWA_DATA_DIR")),
	}, logger)
}

func newApplicationWithConfig(config applicationConfig, logger *slog.Logger) (*application, error) {
	templates, err := loadTemplates()
	if err != nil {
		return nil, err
	}

	center, err := newCommandCenter(config, logger)
	if err != nil {
		return nil, err
	}
	var platform *platformService
	if center.hasService() {
		platform, err = newPlatformService(center, logger)
		if err != nil {
			return nil, err
		}
	}
	workspace, _, err := center.defaultWorkspace()
	if err != nil {
		return nil, err
	}

	return &application{
		logger:    logger,
		templates: templates,
		center:    center,
		workspace: workspace,
		platform:  platform,
	}, nil
}

func newCommandCenter(config applicationConfig, logger *slog.Logger) (*commandCenter, error) {
	center := &commandCenter{
		logger: logger,
		cache:  map[string]*workspace{},
	}

	if strings.TrimSpace(config.DBDSN) == "" {
		workspace, err := openWorkspace(config.WorkspaceTarget, config.SeedFiles, logger)
		if err != nil {
			return nil, err
		}
		center.bundle = workspace
		center.bundleMeta = workspaceMetaRecord{
			ID:          workspace.id,
			Slug:        chooseString(workspace.slug, slugifyWorkspaceName(workspace.name)),
			Name:        chooseString(workspace.name, strings.TrimSuffix(filepath.Base(workspace.workspace), filepath.Ext(workspace.workspace))),
			BundlePath:  chooseString(workspace.bundlePath, workspace.workspace),
			CreatedAt:   "",
			UpdatedAt:   "",
			Description: "Local bundle workspace",
		}
		center.cache[center.bundleMeta.ID] = workspace
		return center, nil
	}

	service, err := openServiceStore(config.DBDSN, config.DataDir)
	if err != nil {
		return nil, err
	}
	center.service = service
	center.dataDir = service.dataDir

	workspaces, err := service.listWorkspaces()
	if err != nil {
		return nil, err
	}
	target := strings.TrimSpace(config.WorkspaceTarget)
	if target == "" || target == defaultWorkspaceFile {
		target = "default"
	}
	var meta workspaceMetaRecord
	switch {
	case len(workspaces) == 0:
		meta, err = service.ensureWorkspace(target)
	case target != "":
		meta, err = service.ensureWorkspace(target)
	default:
		meta = workspaces[0]
	}
	if err != nil {
		return nil, err
	}
	if _, _, err := center.loadWorkspace(meta, config.SeedFiles); err != nil {
		return nil, err
	}
	return center, nil
}

func (c *commandCenter) hasService() bool {
	return c != nil && c.service != nil
}

func (c *commandCenter) listWorkspaces() ([]workspaceMetaRecord, error) {
	if c == nil {
		return nil, nil
	}
	if c.service == nil {
		return []workspaceMetaRecord{c.bundleMeta}, nil
	}
	return c.service.listWorkspaces()
}

func (c *commandCenter) defaultWorkspace() (*workspace, workspaceMetaRecord, error) {
	if c.service == nil {
		if c.bundle == nil {
			return nil, workspaceMetaRecord{}, errors.New("bundle workspace is unavailable")
		}
		return c.bundle, c.bundleMeta, nil
	}
	items, err := c.service.listWorkspaces()
	if err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	if len(items) == 0 {
		return nil, workspaceMetaRecord{}, errors.New("no workspaces were created")
	}
	return c.loadWorkspace(items[0], nil)
}

func (c *commandCenter) workspaceFromRequest(request *http.Request) (*workspace, workspaceMetaRecord, error) {
	if c.service == nil {
		return c.bundle, c.bundleMeta, nil
	}
	if cookie, err := request.Cookie(workspaceCookieName); err == nil {
		if meta, err := c.service.workspaceByID(cookie.Value); err == nil {
			return c.loadWorkspace(meta, nil)
		}
	}
	if selected := strings.TrimSpace(request.URL.Query().Get("workspace")); selected != "" {
		if meta, err := c.service.workspaceByID(selected); err == nil {
			return c.loadWorkspace(meta, nil)
		}
		if meta, err := c.service.workspaceBySlug(selected); err == nil {
			return c.loadWorkspace(meta, nil)
		}
	}
	return c.defaultWorkspace()
}

func (c *commandCenter) setWorkspaceCookie(writer http.ResponseWriter, workspaceID string) {
	http.SetCookie(writer, &http.Cookie{
		Name:     workspaceCookieName,
		Value:    workspaceID,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	})
}

func (c *commandCenter) createWorkspace(name string, description string, seedFiles []string) (*workspace, workspaceMetaRecord, error) {
	if c.service == nil {
		return nil, workspaceMetaRecord{}, errors.New("workspace creation is only available in service mode")
	}
	meta, err := c.service.createWorkspace(name, description)
	if err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	return c.loadWorkspace(meta, seedFiles)
}

func (c *commandCenter) importBundle(path string, name string) (*workspace, workspaceMetaRecord, error) {
	if c.service == nil {
		return nil, workspaceMetaRecord{}, errors.New("bundle import is only available in service mode")
	}
	meta, err := c.service.importWorkspaceBundle(path, name)
	if err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	return c.loadWorkspace(meta, nil)
}

func (c *commandCenter) exportWorkspace(meta workspaceMetaRecord) error {
	if c.service == nil {
		return nil
	}
	return c.service.exportWorkspaceBundle(meta)
}

func (c *commandCenter) loadWorkspace(meta workspaceMetaRecord, seedFiles []string) (*workspace, workspaceMetaRecord, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.service == nil {
		return c.bundle, c.bundleMeta, nil
	}
	if cached := c.cache[meta.ID]; cached != nil {
		return cached, meta, nil
	}

	runsDir := c.service.workspaceArtifactsDir(meta.ID)
	if err := os.MkdirAll(runsDir, 0o755); err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	displayRoot := chooseString(meta.BundlePath, meta.Name)
	workspace, err := openWorkspaceWithStore(meta, displayRoot, runsDir, c.service.workspaceStore(meta), seedFiles, c.logger)
	if err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	c.cache[meta.ID] = workspace
	return workspace, meta, nil
}

func (c *commandCenter) loadWorkspaceByID(id string) (*workspace, workspaceMetaRecord, error) {
	if c == nil {
		return nil, workspaceMetaRecord{}, errors.New("command center is unavailable")
	}
	if c.service == nil {
		if c.bundle != nil && c.bundle.id == strings.TrimSpace(id) {
			return c.bundle, c.bundleMeta, nil
		}
		return nil, workspaceMetaRecord{}, errors.New("bundle workspace is unavailable")
	}
	meta, err := c.service.workspaceByID(strings.TrimSpace(id))
	if err != nil {
		return nil, workspaceMetaRecord{}, err
	}
	return c.loadWorkspace(meta, nil)
}
