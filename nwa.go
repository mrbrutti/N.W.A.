package main

import (
	"flag"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	port := flag.String("p", "8080", "Port to host the web UI on")
	workspaceDir := flag.String("workspace", defaultWorkspaceFile, "Workspace file to open or create (for example acme.nwa)")
	dbDSN := flag.String("db", strings.TrimSpace(os.Getenv("NWA_DB_DSN")), "Database DSN for service mode (PostgreSQL or SQLite path)")
	dataDir := flag.String("data-dir", strings.TrimSpace(os.Getenv("NWA_DATA_DIR")), "Data directory for service artifacts, bundles, and local service DB files")
	flag.StringVar(port, "port", "8080", "Port to host the web UI on")
	flag.StringVar(workspaceDir, "w", defaultWorkspaceFile, "Workspace file to open or create (for example acme.nwa)")
	var seedFiles multiStringFlag
	flag.Var(&seedFiles, "f", "Path, directory, or glob for one or more supported scan sources to load")
	flag.Var(&seedFiles, "file", "Path, directory, or glob for one or more supported scan sources to load")
	if err := flag.CommandLine.Parse(normalizeCLIArgs(os.Args[1:])); err != nil {
		os.Exit(2)
	}
	seedFiles = append(seedFiles, flag.Args()...)

	logger := slog.New(slog.NewTextHandler(os.Stdout, &slog.HandlerOptions{
		Level: slog.LevelInfo,
	}))

	startedAt := time.Now()
	app, err := newApplicationWithConfig(applicationConfig{
		SeedFiles:       seedFiles,
		WorkspaceTarget: *workspaceDir,
		DBDSN:           strings.TrimSpace(*dbDSN),
		DataDir:         strings.TrimSpace(*dataDir),
	}, logger)
	if err != nil {
		logger.Error("initialization failed", "error", err)
		os.Exit(1)
	}

	handler, err := app.routes()
	if err != nil {
		logger.Error("route setup failed", "error", err)
		os.Exit(1)
	}

	status := app.workspace.workspaceStatus()
	logger.Info("scan loaded",
		"workspace", chooseString(status.Name, app.workspace.root),
		"workspace_mode", status.Mode,
		"seed_files", []string(seedFiles),
		"scans", status.ScanCount,
		"hosts", app.workspace.currentSnapshot().meta.LiveHosts,
		"startup", time.Since(startedAt),
	)

	server := &http.Server{
		Addr:              ":" + *port,
		Handler:           handler,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	logger.Info("hosting N.W.A.", "url", "http://localhost:"+*port)
	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		logger.Error("server exited", "error", err)
		os.Exit(1)
	}
}

type multiStringFlag []string

func (m *multiStringFlag) String() string {
	return strings.Join(*m, ",")
}

func (m *multiStringFlag) Set(value string) error {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	*m = append(*m, value)
	return nil
}

func normalizeCLIArgs(args []string) []string {
	normalized := make([]string, 0, len(args))
	for index := 0; index < len(args); index++ {
		arg := args[index]
		switch arg {
		case "-f", "-file":
			if index+1 >= len(args) {
				normalized = append(normalized, arg)
				continue
			}
			for index+1 < len(args) && !strings.HasPrefix(args[index+1], "-") {
				normalized = append(normalized, arg, args[index+1])
				index++
			}
		case "-p", "-port", "-w", "-workspace":
			normalized = append(normalized, arg)
			if index+1 < len(args) {
				index++
				normalized = append(normalized, args[index])
			}
		default:
			normalized = append(normalized, arg)
		}
	}
	return normalized
}
