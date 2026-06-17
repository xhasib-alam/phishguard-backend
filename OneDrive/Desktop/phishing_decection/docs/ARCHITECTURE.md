# PhishGuard Architecture

```mermaid
flowchart TD
    A["Web Dashboard / Android / Flutter / Chrome Extension"] --> B["Flask API v1"]
    B --> C["Routes Layer"]
    C --> D["Services Layer"]
    D --> E["Detection Engine"]
    D --> F["Database Layer"]
    C --> G["Auth Layer"]
    B --> H["Middleware: Rate Limit, Headers, Logging"]
```

PhishGuard uses route modules for HTTP contracts, services for business logic, a detection engine for URL intelligence, and SQLite for development persistence. The API is versioned under `/api/v1` for Android and Flutter clients.
