# NWA React Shell

This package is the React + TypeScript migration shell for the NWA platform.

## Development

Run the Go service first, then start the Vite dev server:

```bash
NWA_ADMIN_PASSWORD=adminpass ./scripts/run-platform.sh
npm --prefix webapp install
npm --prefix webapp run dev
```

The Vite app runs on `http://127.0.0.1:5173/app/` and proxies API requests to the Go service.

## Production-style local build

```bash
npm --prefix webapp install
npm --prefix webapp run build
```

After the build, the Go service can serve the generated shell from `/app`.
