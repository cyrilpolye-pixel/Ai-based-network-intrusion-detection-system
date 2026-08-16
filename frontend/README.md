# AI-NIDS Frontend

This is the React + TypeScript + Vite frontend for the AI-Based Network Intrusion Detection System.

## Features

- Authentication screens for login and signup.
- Protected dashboard pages for monitoring and analysis.
- Live monitoring, traffic analysis, alerts, incident details, reports, settings, and profile screens.
- Page-specific CSS files under `src/pages/` for maintainable styling.

## Getting Started

```bash
cd frontend
npm install
npm run dev
```

The Vite development server prints the local URL after startup.

## Useful Commands

```bash
npm run dev      # Start the development server
npm run build    # Type-check and build production assets
npm run lint     # Run ESLint
npm run preview  # Preview the production build locally
```

## Source Layout

```text
src/
├── components/     # Shared UI components
├── context/        # React context providers
├── layouts/        # App layout shells
├── pages/          # Route-level pages and their CSS files
├── services/       # API and socket clients
├── App.tsx         # Route definitions
└── main.tsx        # React entry point
```

## Styling Guidelines

Route-level styles should live beside their page component, for example `Login.tsx` imports `Login.css`. Shared global styles belong in `src/index.css` or a shared component stylesheet.
