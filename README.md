# AuditFlow REST API

A lightweight, reliable event ingestion and audit log REST service engineered in Python using Flask. Designed to demonstrate clean API architecture, request tracing, strict input sanitization, and query pagination.

## 🚀 Key Features

- **Strict Schema Validation**: Validates JSON payloads on ingestion, rejecting malformed data with structured, actionable 4xx HTTP responses.
- **Filtering & Pagination**: Efficiently slice and filter large datasets via query parameters (`?severity=critical&limit=10&offset=0`).
- **Telemetry & Request Tracing**: Injects unique `X-Request-ID` and `X-Response-Time-MS` response headers for full request lifecycle visibility.
- **Operational Health Probing**: Exposes a `/healthz` endpoint for integration into container orchestration (Docker/Kubernetes).
- **Consistent Envelope Pattern**: Standardized response structures across all successes and failure states.

---

## 🛠️ API Reference

### Health Check
- **Endpoint**: `GET /healthz`
- **Response**: `200 OK`
```json
{
  "records_stored": 42,
  "status": "healthy",
  "timestamp": "2026-09-03T20:54:51.000Z"
}
