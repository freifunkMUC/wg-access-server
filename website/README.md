# Web UI (Vite 8)

The `website/` package now runs on Vite 8 with Rolldown and Oxc handling all bundling, dependency optimization, and JSX transforms.

## Common Scripts

- `npm run dev` / `npm start` – Launches the dev server on http://localhost:3000 with hot module reloading.
- `npm run build` – Type-checks with `tsc` and outputs the production bundle to `website/build` using Rolldown + Lightning CSS.
- `npm run preview` – Serves the production build locally (default port 5000).
- `npm run lint` / `npm run prettier` – Static analysis and formatting helpers.
- `npm run codegen` – Regenerates the gRPC TypeScript SDK from `../proto/*.proto`.

