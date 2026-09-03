# AuditFlow API

A production-ready event ingestion and audit log microservice built with Python and Flask. 

AuditFlow moves beyond a basic CRUD application by implementing an enterprise-style architecture. It uses MongoDB for persistent document storage, enforces API key authentication for security, and is fully containerized with Docker for seamless deployment. 

## 🚀 Key Features

* **Persistent Document Storage:** Integrates MongoDB to handle flexible, schema-less event payloads, demonstrating scalable data modeling.
* **Containerized Architecture:** Utilizes Docker and Docker Compose to orchestrate the Flask API and MongoDB database within an isolated network.
* **Secure Endpoints:** Implements a custom Python decorator to enforce strict `X-API-Key` header authentication on all data-mutating and retrieval endpoints.
* **Analytics Export:** Features an `/export` endpoint that streams raw database records directly to CSV, perfectly formatted for immediate ingestion and data verification in tools like Microsoft Excel or Power BI.
* **Telemetry & Observability:** Automatically injects `X-Request-ID` and `X-Response-Time-MS` headers into every response to track the full request lifecycle.

## 🛠️ Tech Stack

* **Backend:** Python 3.11, Flask
* **Database:** MongoDB 6.0, PyMongo
* **Infrastructure:** Docker, Docker Compose
* **Data Format:** JSON, CSV

### Prerequisites
* Docker and Docker Compose installed on your machine.

### Installation & Run

1. **Clone the repository:**
   ```bash
   git clone [https://github.com/yourusername/auditflow-api.git](https://github.com/yourusername/auditflow-api.git)
   cd auditflow-api

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

