import argparse
import logging
import os
from typing import Dict, List

from flask import Flask, jsonify, render_template, request

from app import get_sync_config
from state_manager import StateManager
from sync_service import SyncService

# Global references (set in create_app)
state_manager: StateManager = None
sync_service: SyncService = None


def create_app(interval_seconds: int = 3600) -> Flask:
    """Create and configure the Flask application."""
    app = Flask(__name__)
    app.config["TEMPLATES_AUTO_RELOAD"] = True

    # Reduce Flask/werkzeug HTTP request logging verbosity
    log = logging.getLogger("werkzeug")
    log.setLevel(logging.WARNING)

    # Initialize state manager and sync service
    global state_manager, sync_service
    state_manager = StateManager()

    try:
        sync_config = get_sync_config()
        sync_service = SyncService(sync_config, state_manager, interval_seconds)
        sync_service.start()
        logging.info("Flask app initialized with sync service")
    except Exception as exc:
        logging.error(f"Failed to initialize sync service: {exc}")
        raise

    # Dashboard route
    @app.route("/")
    def dashboard():
        """Main dashboard page."""
        return render_template("dashboard.html")

    # HTMX Partial routes (return HTML fragments)
    @app.route("/partials/status")
    def partial_status():
        """Sync status card (polled every 2s)."""
        status = state_manager.get_current_status()
        return render_template("partials/status.html", status=status)

    @app.route("/partials/logs")
    def partial_logs():
        """Recent logs (polled every 2s)."""
        limit = int(request.args.get("limit", 100))
        logs = state_manager.get_recent_logs(limit=limit)
        return render_template("partials/logs.html", logs=logs)

    @app.route("/partials/history")
    def partial_history():
        """Sync history table."""
        limit = int(request.args.get("limit", 20))
        history = state_manager.get_sync_history(limit=limit)
        return render_template("partials/history.html", history=history)

    # API endpoints for actions
    @app.route("/api/trigger", methods=["POST"])
    def trigger_sync():
        """Manually trigger a sync."""
        try:
            data = request.get_json() or {}
            mode = data.get("mode", sync_service.sync_config.mode)

            # Validate mode
            valid_modes = ["dns", "interfaces", "rules", "enrichment", "all"]
            if mode not in valid_modes:
                return jsonify({"success": False, "error": f"Invalid mode: {mode}"}), 400

            sync_id = sync_service.trigger_sync(mode)
            return jsonify({"success": True, "sync_id": sync_id, "mode": mode})
        except RuntimeError as exc:
            return jsonify({"success": False, "error": str(exc)}), 409
        except Exception as exc:
            logging.error(f"Failed to trigger sync: {exc}", exc_info=True)
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/collections/<collection>")
    def view_collection(collection: str):
        """View KV store collection data with pagination."""
        try:
            limit = int(request.args.get("limit", 100))
            offset = int(request.args.get("offset", 0))

            # Validate collection name
            valid_collections = [
                "pfsense_dns_hosts",
                "pfsense_interface_map",
                "pfsense_filter_rule_map",
                "pfsense_zone_subnets",
            ]
            if collection not in valid_collections:
                return jsonify({"success": False, "error": f"Invalid collection: {collection}"}), 404

            # Query collection
            kv = sync_service.sync_config.kv
            data = kv.query_collection(collection, limit=limit, offset=offset)
            total = kv.count_documents(collection)

            return render_template(
                "partials/collections.html",
                collection=collection,
                data=data,
                total=total,
                limit=limit,
                offset=offset,
            )
        except Exception as exc:
            logging.error(f"Failed to query collection {collection}: {exc}", exc_info=True)
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/collections/<collection>/wipe", methods=["POST"])
    def wipe_collection(collection: str):
        """Delete all records from a collection."""
        try:
            # Validate collection name
            valid_collections = [
                "pfsense_dns_hosts",
                "pfsense_interface_map",
                "pfsense_filter_rule_map",
                "pfsense_zone_subnets",
            ]
            if collection not in valid_collections:
                return jsonify({"success": False, "error": f"Invalid collection: {collection}"}), 404

            # Delete all documents
            kv = sync_service.sync_config.kv
            count = kv.delete_all(collection)
            logging.info(f"Wiped {count} documents from collection '{collection}'")

            return jsonify({"success": True, "deleted": count, "collection": collection})
        except Exception as exc:
            logging.error(f"Failed to wipe collection {collection}: {exc}", exc_info=True)
            return jsonify({"success": False, "error": str(exc)}), 500

    @app.route("/api/status")
    def api_status():
        """Get current status as JSON."""
        status = state_manager.get_current_status()
        return jsonify(status)

    return app


def main():
    """Web app entrypoint."""
    logging.info("Starting pfSense KV Store Sync web interface")

    parser = argparse.ArgumentParser(description="pfSense KV Store Sync web interface")
    parser.add_argument("--host", default=os.environ.get("WEB_HOST", "0.0.0.0"))
    parser.add_argument("--port", type=int, default=int(os.environ.get("WEB_PORT", "5000")))
    parser.add_argument(
        "--debug",
        action="store_true",
        default=os.environ.get("WEB_DEBUG", "false").lower() in ("true", "1", "yes"),
    )
    parser.add_argument(
        "--interval-seconds", type=int, default=int(os.environ.get("SYNC_INTERVAL_SECONDS", "3600"))
    )
    args = parser.parse_args()

    logging.info(f"Configuration: host={args.host}, port={args.port}, debug={args.debug}, interval={args.interval_seconds}s")

    try:
        app = create_app(interval_seconds=args.interval_seconds)
        logging.info(f"Starting Flask web server on {args.host}:{args.port}")
        app.run(host=args.host, port=args.port, debug=args.debug)
    except KeyboardInterrupt:
        logging.info("Received interrupt signal, shutting down gracefully")
    except Exception as exc:
        logging.error(f"Failed to start web server: {exc}", exc_info=True)
        raise SystemExit(1)


if __name__ == "__main__":
    main()
