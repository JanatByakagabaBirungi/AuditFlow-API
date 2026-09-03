import os
import time
import uuid
import csv
import io
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response
from pymongo import MongoClient
from functools import wraps
from flasgger import Swagger
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address

app = Flask(__name__)

# --- Setup Rate Limiting ---
limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"],
    storage_uri="memory://"
)

# --- Setup Swagger Documentation ---
swagger_config = {
    "headers": [],
    "specs": [{"endpoint": 'apispec_1', "route": '/apispec_1.json', "rule_filter": lambda rule: True, "model_filter": lambda tag: True}],
    "static_url_path": "/flasgger_static",
    "swagger_ui": True,
    "specs_route": "/apidocs/"
}

swagger_template = {
    "swagger": "2.0",
    "info": {
        "title": "AuditFlow API",
        "description": "Production-ready event ingestion and audit log service.",
        "version": "1.0.0"
    },
    "securityDefinitions": {
        "APIKeyHeader": {
            "type": "apiKey",
            "name": "X-API-Key",
            "in": "header"
        }
    }
}
swagger = Swagger(app, config=swagger_config, template=swagger_template)

# --- Database & Auth Setup ---
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client.auditflow
events_collection = db.events

VALID_SEVERITIES = {"info", "warning", "critical"}
API_KEY = os.getenv("API_KEY", "portfolio-secret-key-2026")

def require_api_key(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        key = request.headers.get("X-API-Key")
        if key != API_KEY:
            return jsonify({"success": False, "error": {"code": "UNAUTHORIZED", "message": "Invalid or missing API Key"}}), 401
        return f(*args, **kwargs)
    return decorated

@app.before_request
def start_timer():
    request.start_time = time.time()
    request.request_id = request.headers.get("X-Request-ID", str(uuid.uuid4()))

@app.after_request
def inject_metadata(response):
    elapsed_time = (time.time() - request.start_time) * 1000
    response.headers["X-Request-ID"] = request.request_id
    response.headers["X-Response-Time-MS"] = f"{elapsed_time:.2f}"
    return response

@app.route("/healthz", methods=["GET"])
@limiter.exempt
def health_check():
    """
    System health check
    ---
    responses:
      200:
        description: Returns system and database health status
    """
    db_status = "connected"
    try:
        client.admin.command('ping')
    except Exception:
        db_status = "disconnected"
        
    return jsonify({
        "status": "healthy" if db_status == "connected" else "degraded",
        "database": db_status,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "records_stored": events_collection.count_documents({})
    }), 200 if db_status == "connected" else 503

@app.route("/api/v1/events", methods=["POST"])
@require_api_key
@limiter.limit("10 per minute")
def create_event():
    """
    Ingest a new audit event
    ---
    security:
      - APIKeyHeader: []
    parameters:
      - in: body
        name: body
        required: true
        schema:
          type: object
          properties:
            source:
              type: string
              example: auth-service
            action:
              type: string
              example: user.login.failed
            severity:
              type: string
              example: warning
            metadata:
              type: object
    responses:
      201:
        description: Event created successfully
      400:
        description: Bad request / Missing fields
      401:
        description: Unauthorized
    """
    payload = request.get_json() or {}
    
    required_fields = ["source", "action", "severity"]
    missing = [field for field in required_fields if field not in payload]
    if missing:
        return jsonify({"success": False, "error": {"code": "MISSING_FIELDS", "message": f"Missing: {', '.join(missing)}"}}), 400

    if payload["severity"].lower() not in VALID_SEVERITIES:
        return jsonify({"success": False, "error": {"code": "INVALID_SEVERITY", "message": "Invalid severity level"}}), 400

    new_event = {
        "event_id": str(uuid.uuid4()),
        "source": str(payload["source"]).strip(),
        "action": str(payload["action"]).strip(),
        "severity": payload["severity"].lower(),
        "metadata": payload.get("metadata", {}),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }

    events_collection.insert_one(new_event.copy())
    new_event.pop("_id", None)
    return jsonify({"success": True, "data": new_event}), 201

@app.route("/api/v1/events", methods=["GET"])
@require_api_key
def list_events():
    """
    List events with filtering and pagination
    ---
    security:
      - APIKeyHeader: []
    parameters:
      - in: query
        name: severity
        type: string
        required: false
      - in: query
        name: limit
        type: integer
        default: 10
      - in: query
        name: offset
        type: integer
        default: 0
    responses:
      200:
        description: A list of events
      401:
        description: Unauthorized
    """
    query = {}
    if request.args.get("severity"):
        query["severity"] = request.args.get("severity").lower()
    if request.args.get("source"):
        query["source"] = request.args.get("source").lower()

    limit = max(1, min(int(request.args.get("limit", 10)), 100))
    offset = max(0, int(request.args.get("offset", 0)))

    cursor = events_collection.find(query, {"_id": 0}).skip(offset).limit(limit).sort("created_at", -1)
    results = list(cursor)
    total_count = events_collection.count_documents(query)

    return jsonify({
        "success": True,
        "meta": {"total_count": total_count, "limit": limit, "offset": offset},
        "data": results
    }), 200

@app.route("/api/v1/events/export", methods=["GET"])
@require_api_key
@limiter.limit("2 per minute")
def export_events_csv():
    """
    Export all events to CSV
    ---
    security:
      - APIKeyHeader: []
    responses:
      200:
        description: CSV file download
      401:
        description: Unauthorized
    """
    cursor = events_collection.find({}, {"_id": 0}).sort("created_at", -1)
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["Event ID", "Timestamp", "Source", "Action", "Severity", "Metadata"])
    
    for event in cursor:
        writer.writerow([
            event.get("event_id"),
            event.get("created_at"),
            event.get("source"),
            event.get("action"),
            event.get("severity"),
            str(event.get("metadata"))
        ])
    
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment;filename=audit_events_export.csv"}
    )

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)
