# OIDC Test

A browser-based OpenID Connect provider testing tool. Configure an OIDC provider, run auth flows (Authorization Code + PKCE, Implicit, Hybrid, Client Credentials), inspect tokens, fetch userinfo, and review full request/response logs.

## Stack

- React 18 + TypeScript
- Vite
- Tailwind CSS + shadcn/ui
- React Router
- lucide-react

## Running with Docker (recommended)

```sh
docker compose up --build
```

Server starts at `http://localhost:5885`. Edit source files locally -- Vite HMR auto-reloads the browser.

To stop:

```sh
docker compose down
```

## Running locally (without Docker)

Requires [Bun](https://bun.sh):

```sh
bun install
bun run dev
```

## Scripts

| Command | Description |
|---|---|
| `bun run dev` | Start dev server (port 5885) |
| `bun run build` | Production build to `dist/` |
| `bun run build:dev` | Development build |
| `bun run preview` | Preview production build |
| `bun run lint` | Run ESLint |

## Features

- **Provider Discovery** -- Fetches `.well-known/openid-configuration` automatically, with manual endpoint override for CORS-blocked providers
- **Auth Flows** -- Authorization Code + PKCE (recommended), Implicit, Hybrid, Client Credentials
- **Token Inspection** -- View decoded JWT headers/payloads, copy tokens
- **UserInfo** -- Query the userinfo endpoint with the access token
- **Request Logs** -- Full request/response details with timing, exportable as JSON
