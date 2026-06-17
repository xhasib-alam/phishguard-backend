# PhishGuard API

All API responses use:

```json
{
  "success": true,
  "message": "Operation completed",
  "data": {},
  "error": null,
  "request_id": "uuid"
}
```

## Endpoints

- `POST /api/v1/auth/register`
- `POST /api/v1/auth/login`
- `POST /api/v1/auth/logout`
- `POST /api/v1/auth/password-reset`
- `POST /api/v1/scan`
- `GET /api/v1/history`
- `GET /api/v1/history/analytics`
- `POST /api/v1/reports`
- `GET /api/v1/reports/{id}`
- `POST /api/v1/reports/pdf`
- `GET /api/v1/admin/overview`
