import os
import time
import uuid
import csv
import io
from datetime import datetime, timezone
from flask import Flask, jsonify, request, Response
from pymongo import MongoClient
from functools import wraps

app = Flask(__name__)

# Database Configuration
MONGO_URI = os.getenv("MONGO_URI", "mongodb://localhost:27017/")
client = MongoClient(MONGO_URI)
db = client.auditflow
events_collection = db.events

VALID_SEVERITIES = {"info", "warning", "critical"}
API_KEY = os.getenv("API_KEY", "dev-secret-key-123")

def require_api_key(f):
    """Decorator to enforce API key authentication."""
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
def health_check():
    """System health check including database connectivity."""
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
def create_event():
    """Ingests and validates an audit event."""
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
    
    # Remove MongoDB's internal _id before returning to client
    new_event.pop("_id", None)
    return jsonify({"success": True, "data": new_event}), 201

@app.route("/api/v1/events", methods=["GET"])
@require_api_key
def list_events():
    """Fetches events with MongoDB query filtering and pagination."""
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
def export_events_csv():
    """Exports all audit events as a CSV stream for data analysis tools."""
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
