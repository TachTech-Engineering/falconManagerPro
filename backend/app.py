from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from falconpy import Alerts, Hosts, Incidents, EventStreams, OAuth2, IOC, Intel, RealTimeResponse
from datetime import datetime, timedelta
import logging
import time
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# ---------------------------------------------------------------------------
# Logging / global state
# ---------------------------------------------------------------------------
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

falcon_auth = None          # OAuth2 object after /api/auth
saved_views = {}            # In-memory saved views
playbooks = {}              # In-memory playbooks

# Hard API limits (from CrowdStrike errors you saw)
MAX_DETECT_LIMIT = 5000
MAX_HOST_DETAIL_BATCH = 5000

# ---------------------------------------------------------------------------
# AUTHENTICATION
# ---------------------------------------------------------------------------

@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Authenticate with CrowdStrike Falcon API"""
    global falcon_auth

    data = request.json or {}
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    base_url = data.get('base_url', 'https://api.crowdstrike.com')

    if not client_id or not client_secret:
        return jsonify({'status': 'error', 'message': 'client_id and client_secret are required'}), 400

    try:
        falcon_auth = OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )

        token = falcon_auth.token()
        if token:
            logger.info("Authentication successful")
            return jsonify({'status': 'success', 'message': 'Authentication successful'})
        else:
            logger.error("Authentication failed: no token returned")
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 401

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ---------------------------------------------------------------------------
# DETECTIONS - READ & MANAGE
# ---------------------------------------------------------------------------

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Fetch detections from CrowdStrike Falcon (Alerts)"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        logger.debug("Starting get_detections")
        falcon_detect = Alerts(auth_object=falcon_auth)
        logger.debug("Created Alerts object")

        severity = request.args.get('severity')
        status = request.args.get('status')
        hours = int(request.args.get('hours', 24))
        
        # Cap at 30 days (720 hours) to avoid API issues and respect retention
        hours = min(hours, 720)

        # Time filter
        time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(hours=hours)).isoformat()}Z'"
        filters = [time_filter]

        if severity:
            filters.append(f"max_severity_displayname:'{severity}'")
        if status:
            filters.append(f"status:'{status}'")

        filter_string = "+".join(filters)
        logger.debug(f"Filter string: {filter_string}")

        # Respect API limit (< 10000, using 5000 to be safe)
        response = falcon_detect.query_alerts(
            filter=filter_string,
            limit=MAX_DETECT_LIMIT,
            sort='created_timestamp.desc'
        )

        logger.debug(f"query_alerts response code: {response.get('status_code')}")
        if response.get('status_code') != 200:
            logger.error(f"Query failed with body: {response.get('body')}")
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        logger.debug(f"Found {len(detection_ids)} detection IDs")

        if not detection_ids:
            return jsonify({'detections': []})

        details_response = falcon_detect.get_alerts(ids=detection_ids)
        logger.debug(f"get_alerts response code: {details_response.get('status_code')}")

        if details_response.get('status_code') != 200:
            logger.error(f"Get detection details failed with body: {details_response.get('body')}")
            return jsonify({'error': 'Failed to get detection details'}), 500

        detections = []
        for det in details_response['body'].get('resources', []):
            behaviors = det.get('behaviors', [{}])
            first_behavior = behaviors[0] if behaviors else {}
            device = det.get('device', {}) or {}

            detections.append({
                'id': det.get('detection_id') or det.get('id'),
                'name': first_behavior.get('tactic', 'Unknown'),
                'severity': (det.get('max_severity_displayname') or 'unknown').lower(),
                'status': det.get('status'),
                'timestamp': det.get('created_timestamp'),
                'host': device.get('hostname', 'Unknown'),
                'host_id': device.get('device_id'),
                'behavior': first_behavior.get('tactic', 'Unknown'),
                'description': first_behavior.get('description', ''),
                'assigned_to': det.get('assigned_to_name', 'Unassigned')
            })

        logger.debug(f"Successfully processed {len(detections)} detections")
        return jsonify({'detections': detections})

    except Exception as e:
        logger.exception("Error fetching detections")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/<detection_id>/status', methods=['PATCH'])
def update_detection_status(detection_id):
    """Update detection status with comment and assignment"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        new_status = data.get('status')
        comment = data.get('comment', '')
        assigned_to = data.get('assigned_to')

        if not new_status:
            return jsonify({'error': 'Status is required'}), 400

        falcon_detect = Alerts(auth_object=falcon_auth)

        response = falcon_detect.update_Alerts_by_ids(
            ids=[detection_id],
            status=new_status,
            assigned_to_uuid=assigned_to,
            comment=comment
        )

        if response.get('status_code') not in [200, 202]:
            logger.error(f"Failed to update detection {detection_id}: {response}")
            return jsonify({'error': 'Failed to update detection status'}), 500

        return jsonify({
            'status': 'success',
            'message': f'Detection updated to {new_status}',
            'detection_id': detection_id
        })

    except Exception as e:
        logger.exception("Error updating detection")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/bulk-update', methods=['POST'])
def bulk_update_detections():
    """Bulk update multiple detections"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        detection_ids = data.get('detection_ids', [])
        new_status = data.get('status')
        comment = data.get('comment', '')

        if not detection_ids or not new_status:
            return jsonify({'error': 'detection_ids and status required'}), 400

        falcon_detect = Alerts(auth_object=falcon_auth)

        response = falcon_detect.update_detections(
            ids=detection_ids,
            status=new_status,
            comment=comment
        )

        if response.get('status_code') not in [200, 202]:
            logger.error(f"Bulk update failed: {response}")
            return jsonify({'error': 'Failed to bulk update'}), 500

        return jsonify({
            'status': 'success',
            'message': f'{len(detection_ids)} detections updated',
            'count': len(detection_ids)
        })

    except Exception as e:
        logger.exception("Error in bulk update")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# IOC MANAGEMENT
# ---------------------------------------------------------------------------

@app.route('/api/iocs', methods=['GET'])
def get_iocs():
    """Get custom IOCs"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        falcon_ioc = IOC(auth_object=falcon_auth)
        ioc_type = request.args.get('type')

        filters = []
        if ioc_type:
            filters.append(f"type:'{ioc_type}'")

        filter_string = "+".join(filters) if filters else None

        response = falcon_ioc.indicator_search(
            filter=filter_string,
            limit=MAX_DETECT_LIMIT
        )

        if response.get('status_code') != 200:
            logger.error(f"IOC search failed: {response}")
            return jsonify({'error': 'Failed to query IOCs'}), 500

        ioc_ids = response['body'].get('resources', []) or []
        if not ioc_ids:
            return jsonify({'iocs': []})

        details_response = falcon_ioc.indicator_get(ids=ioc_ids)
        if details_response.get('status_code') != 200:
            logger.error(f"IOC details failed: {details_response}")
            return jsonify({'error': 'Failed to get IOC details'}), 500

        return jsonify({'iocs': details_response['body'].get('resources', [])})

    except Exception as e:
        logger.exception("Error fetching IOCs")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs', methods=['POST'])
def create_ioc():
    """Create new IOC"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        falcon_ioc = IOC(auth_object=falcon_auth)

        body = {
            "indicators": [{
                "type": data.get('type'),
                "value": data.get('value'),
                "policy": data.get('policy', 'detect'),
                "description": data.get('description', ''),
                "severity": data.get('severity', 'medium'),
                "tags": data.get('tags', [])
            }]
        }

        response = falcon_ioc.indicator_create(body=body)

        if response.get('status_code') not in [200, 201]:
            logger.error(f"Create IOC failed: {response}")
            return jsonify({'error': 'Failed to create IOC'}), 500

        resources = response['body'].get('resources', [])
        created = resources[0] if resources else {}

        return jsonify({
            'status': 'success',
            'message': 'IOC created successfully',
            'ioc': created
        })

    except Exception as e:
        logger.exception("Error creating IOC")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/<ioc_id>', methods=['DELETE'])
def delete_ioc(ioc_id):
    """Delete IOC"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        falcon_ioc = IOC(auth_object=falcon_auth)

        response = falcon_ioc.indicator_delete(ids=[ioc_id])

        if response.get('status_code') != 200:
            logger.error(f"Delete IOC failed: {response}")
            return jsonify({'error': 'Failed to delete IOC'}), 500

        return jsonify({
            'status': 'success',
            'message': 'IOC deleted successfully'
        })

    except Exception as e:
        logger.exception("Error deleting IOC")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# PLAYBOOKS (local-only, not stored in Falcon)
# ---------------------------------------------------------------------------

@app.route('/api/playbooks', methods=['GET'])
def get_playbooks():
    """Get all automated response playbooks"""
    return jsonify({'playbooks': list(playbooks.values())})


@app.route('/api/playbooks', methods=['POST'])
def create_playbook():
    """Create automated response playbook"""
    data = request.json or {}
    playbook_id = f"pb_{int(time.time())}"

    playbooks[playbook_id] = {
        'id': playbook_id,
        'name': data.get('name'),
        'trigger': data.get('trigger'),
        'actions': data.get('actions', []),
        'enabled': data.get('enabled', True),
        'created': datetime.utcnow().isoformat()
    }

    return jsonify({
        'status': 'success',
        'playbook': playbooks[playbook_id]
    })


@app.route('/api/playbooks/<playbook_id>/execute', methods=['POST'])
def execute_playbook(playbook_id):
    """Execute a playbook manually"""
    if playbook_id not in playbooks:
        return jsonify({'error': 'Playbook not found'}), 404

    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        playbook = playbooks[playbook_id]
        data = request.json or {}
        target_id = data.get('target_id')

        results = []

        for action in playbook.get('actions', []):
            action_type = action.get('type')

            if action_type == 'contain_host':
                falcon_hosts = Hosts(auth_object=falcon_auth)
                response = falcon_hosts.perform_action(
                    action_name='contain',
                    ids=[target_id]
                )
                results.append({
                    'action': 'contain_host',
                    'status': 'success' if response.get('status_code') == 200 else 'failed'
                })

            elif action_type == 'close_detection':
                falcon_detect = Alerts(auth_object=falcon_auth)
                response = falcon_detect.update_detections(
                    ids=[target_id],
                    status='false_positive',
                    comment=f"Auto-closed by playbook: {playbook['name']}"
                )
                results.append({
                    'action': 'close_detection',
                    'status': 'success' if response.get('status_code') in [200, 202] else 'failed'
                })

        return jsonify({
            'status': 'success',
            'results': results
        })

    except Exception as e:
        logger.exception("Error executing playbook")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# SAVED VIEWS (local-only)
# ---------------------------------------------------------------------------

@app.route('/api/views', methods=['GET'])
def get_saved_views():
    """Get all saved dashboard views"""
    return jsonify({'views': list(saved_views.values())})


@app.route('/api/views', methods=['POST'])
def create_saved_view():
    """Create a saved dashboard view"""
    data = request.json or {}
    view_id = f"view_{int(time.time())}"

    saved_views[view_id] = {
        'id': view_id,
        'name': data.get('name'),
        'filters': data.get('filters', {}),
        'layout': data.get('layout', []),
        'created': datetime.utcnow().isoformat()
    }

    return jsonify({
        'status': 'success',
        'view': saved_views[view_id]
    })


@app.route('/api/views/<view_id>', methods=['DELETE'])
def delete_saved_view(view_id):
    """Delete a saved view"""
    if view_id in saved_views:
        del saved_views[view_id]
        return jsonify({'status': 'success'})
    return jsonify({'error': 'View not found'}), 404

# ---------------------------------------------------------------------------
# REPORT GENERATION
# ---------------------------------------------------------------------------

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate PDF report"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        report_type = data.get('type', 'detections')
        time_range = int(data.get('time_range', 24))

        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []

        title = Paragraph(f"<b>CrowdStrike Falcon {report_type.title()} Report</b>", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))

        metadata = Paragraph(
            f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
            f"Time Range: Last {time_range} hours",
            styles['Normal']
        )
        story.append(metadata)
        story.append(Spacer(1, 12))

        if report_type == 'detections':
            falcon_detect = Alerts(auth_object=falcon_auth)
            time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(hours=time_range)).isoformat()}Z'"

            response = falcon_detect.query_alerts(
                filter=time_filter,
                limit=MAX_DETECT_LIMIT,
                sort='created_timestamp.desc'
            )

            if response.get('status_code') == 200:
                detection_ids = response['body'].get('resources', []) or []
                if detection_ids:
                    details = falcon_detect.get_alerts(ids=detection_ids)
                    if details.get('status_code') == 200:
                        table_data = [['Detection ID', 'Severity', 'Status', 'Host', 'Created']]

                        for det in details['body'].get('resources', [])[:20]:
                            device = det.get('device', {}) or {}
                            table_data.append([
                                (det.get('detection_id') or det.get('id') or '')[:20] + '...',
                                det.get('max_severity_displayname', ''),
                                det.get('status', ''),
                                device.get('hostname', ''),
                                (det.get('created_timestamp') or '')[:19]
                            ])

                        t = Table(table_data)
                        t.setStyle(TableStyle([
                            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
                            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
                            ('FONTSIZE', (0, 0), (-1, 0), 10),
                            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
                            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
                            ('GRID', (0, 0), (-1, -1), 1, colors.black)
                        ]))

                        story.append(t)

        doc.build(story)
        buffer.seek(0)

        return send_file(
            buffer,
            mimetype='application/pdf',
            as_attachment=True,
            download_name=f'falcon_report_{report_type}_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.pdf'
        )

    except Exception as e:
        logger.exception("Error generating report")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# RECENT EVENTS (simple polling stub)
# ---------------------------------------------------------------------------

@app.route('/api/events/recent', methods=['GET'])
def get_recent_events():
    """Get recent detections (used for polling)"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        falcon_detect = Alerts(auth_object=falcon_auth)

        time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(minutes=5)).isoformat()}Z'"

        response = falcon_detect.query_alerts(
            filter=time_filter,
            limit=10,
            sort='created_timestamp.desc'
        )

        if response.get('status_code') == 200:
            return jsonify({
                'status': 'success',
                'detection_ids': response['body'].get('resources', []) or []
            })

        return jsonify({'status': 'success', 'detection_ids': []})

    except Exception as e:
        logger.exception("Error fetching recent events")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# HOSTS MANAGEMENT
# ---------------------------------------------------------------------------

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """Fetch hosts from CrowdStrike Falcon"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        logger.debug("Starting get_hosts")
        falcon_hosts = Hosts(auth_object=falcon_auth)
        logger.debug("Created Hosts object")

        status = request.args.get('status')
        limit = min(int(request.args.get('limit', MAX_HOST_DETAIL_BATCH)), MAX_HOST_DETAIL_BATCH)

        filter_string = None
        if status:
            filter_string = f"status:'{status}'"

        logger.debug(f"Querying hosts with filter: {filter_string}, limit: {limit}")
        response = falcon_hosts.query_devices(
            filter=filter_string,
            limit=limit,
            sort='last_seen.desc'
        )

        logger.debug(f"query_devices response code: {response.get('status_code')}")
        if response.get('status_code') != 200:
            logger.error(f"Query hosts failed with body: {response.get('body')}")
            return jsonify({'error': 'Failed to query hosts'}), 500

        host_ids = response['body'].get('resources', []) or []
        logger.debug(f"Found {len(host_ids)} host IDs")

        if not host_ids:
            return jsonify({'hosts': []})

        hosts = []
        for i in range(0, len(host_ids), MAX_HOST_DETAIL_BATCH):
            batch_ids = host_ids[i:i + MAX_HOST_DETAIL_BATCH]
            details_response = falcon_hosts.get_device_details(ids=batch_ids)
            logger.debug(f"get_device_details response code: {details_response.get('status_code')}")

            if details_response.get('status_code') != 200:
                logger.error(f"Get host details failed with body: {details_response.get('body')}")
                return jsonify({'error': 'Failed to get host details'}), 500

            for host in details_response['body'].get('resources', []):
                hosts.append({
                    'id': host.get('device_id'),
                    'hostname': host.get('hostname'),
                    'ip': host.get('local_ip'),
                    'os': f"{host.get('os_version', '')} {host.get('os_build', '')}".strip(),
                    'status': host.get('status'),
                    'lastSeen': host.get('last_seen'),
                    'agent_version': host.get('agent_version'),
                    'platform': host.get('platform_name')
                })

        logger.debug(f"Successfully processed {len(hosts)} hosts")
        return jsonify({'hosts': hosts})

    except Exception as e:
        logger.exception("Error fetching hosts")
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/contain', methods=['POST'])
def contain_host(device_id):
    """Network-contain a host (isolate from network)."""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        falcon_hosts = Hosts(auth_object=falcon_auth)
        resp = falcon_hosts.perform_action(
            action_name="contain",
            ids=[device_id]
        )

        status = resp.get("status_code", 500)
        if status not in (200, 201, 202):
            logger.error(f"Contain error: {resp}")
            return jsonify({'error': 'Failed to contain host', 'details': resp}), 500

        return jsonify({'status': 'success', 'action': 'contain', 'device_id': device_id})
    except Exception as e:
        logger.error(f"Contain exception: {e}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts/<device_id>/lift-containment', methods=['POST'])
def lift_containment(device_id):
    """Release host from network containment."""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        falcon_hosts = Hosts(auth_object=falcon_auth)
        resp = falcon_hosts.perform_action(
            action_name="lift_containment",
            ids=[device_id]
        )

        status = resp.get("status_code", 500)
        if status not in (200, 201, 202):
            logger.error(f"Lift containment error: {resp}")
            return jsonify({'error': 'Failed to lift containment', 'details': resp}), 500

        return jsonify({'status': 'success', 'action': 'lift_containment', 'device_id': device_id})
    except Exception as e:
        logger.error(f"Lift containment exception: {e}")
        return jsonify({'error': str(e)}), 500


# ---------------------------------------------------------------------------
# HEALTHCHECK
# ---------------------------------------------------------------------------

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    try:
        return jsonify({
            'status': 'healthy',
            'authenticated': falcon_auth is not None,
            'timestamp': str(datetime.utcnow())
        }), 200
    except Exception as e:
        logger.exception("Health check error")
        return jsonify({'error': str(e)}), 500


# ========================================================================
# REAL TIME RESPONSE (RTR) – SIMPLE REMEDIATION HELPERS
# ========================================================================

def _get_rtr():
    """Small helper to build an RTR client using the existing falcon_auth."""
    global falcon_auth
    if not falcon_auth:
        raise RuntimeError("Falcon API not authenticated")
    return RealTimeResponse(auth_object=falcon_auth)


def _rtr_run_write_command(device_id, base_command, command_string):
    """
    Internal helper: start RTR session and run a write command (kill, rm, etc.)
    """
    try:
        rtr = _get_rtr()

        # 1) Init a session for this host
        init_body = {"device_id": [device_id], "queue_offline": False}
        init_resp = rtr.batch_init_sessions(body=init_body)

        if init_resp.get("status_code") not in (200, 201):
            return {
                "ok": False,
                "error": "Failed to init RTR session",
                "details": init_resp
            }

        batch_id = init_resp.get("body", {}).get("batch_id")
        if not batch_id:
            return {
                "ok": False,
                "error": "No batch_id in RTR response",
                "details": init_resp
            }

        # 2) Run the command as an active responder (write)
        cmd_resp = rtr.batch_active_responder_command(
            base_command=base_command,
            batch_id=batch_id,
            command_string=command_string,
            optional_hosts=[device_id],
            timeout=60
        )

        if cmd_resp.get("status_code") != 200:
            return {
                "ok": False,
                "error": "RTR command failed",
                "details": cmd_resp
            }

        return {"ok": True, "result": cmd_resp.get("body", {})}

    except Exception as e:
        logger.exception("RTR command error")
        return {"ok": False, "error": str(e)}


@app.route('/api/hosts/<device_id>/rtr/kill', methods=['POST'])
def rtr_kill_process(device_id):
    """
    Kill a process by name or PID on a host.
    Body: { "process": "process_name_or_pid" }
    """
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json or {}
    process = data.get('process')

    if not process:
        return jsonify({'error': 'process is required'}), 400

    result = _rtr_run_write_command(
        device_id=device_id,
        base_command="kill",
        command_string=f"kill {process}"
    )

    if not result["ok"]:
        return jsonify({'error': result["error"], 'details': result.get("details")}), 500

    return jsonify({'status': 'success', 'action': 'kill', 'result': result["result"]})


@app.route('/api/hosts/<device_id>/rtr/delete-file', methods=['POST'])
def rtr_delete_file(device_id):
    """
    Delete a file on a host.
    Body: { "path": "C:\\path\\bad.exe" }
    """
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    data = request.json or {}
    path = data.get('path')

    if not path:
        return jsonify({'error': 'path is required'}), 400

    result = _rtr_run_write_command(
        device_id=device_id,
        base_command="rm",
        command_string=f"rm {path}"
    )

    if not result["ok"]:
        return jsonify({'error': result["error"], 'details': result.get("details")}), 500

    return jsonify({'status': 'success', 'action': 'delete_file', 'result': result["result"]})


# ---------------------------------------------------------------------------
# ADVANCED DETECTION OPERATIONS (hash tools, advanced search, exclusions)
# ---------------------------------------------------------------------------

@app.route('/api/detections/close-by-hash', methods=['POST'])
def close_by_hash():
    """Close all detections with a specific SHA256 hash"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        hash_value = data.get('hash')
        comment = data.get('comment', 'Closed via hash - approved by SOC')
        status = data.get('status', 'closed')
        dry_run = data.get('dry_run', False)

        if not hash_value:
            return jsonify({'error': 'Hash value required'}), 400

        falcon_detect = Alerts(auth_object=falcon_auth)

        filter_xdr = f'entities.sha256:"{hash_value}"'
        filter_ods = f'sha256:"{hash_value}"'

        ids_xdr = []
        ids_ods = []

        response_xdr = falcon_detect.query_alerts(filter=filter_xdr, limit=MAX_DETECT_LIMIT)
        if response_xdr.get('status_code') == 200:
            ids_xdr = response_xdr['body'].get('resources', []) or []

        response_ods = falcon_detect.query_alerts(filter=filter_ods, limit=MAX_DETECT_LIMIT)
        if response_ods.get('status_code') == 200:
            ids_ods = response_ods['body'].get('resources', []) or []

        all_ids = list(set(ids_xdr + ids_ods))

        if not all_ids:
            return jsonify({
                'status': 'success',
                'message': 'No detections found with this hash',
                'xdr_count': len(ids_xdr),
                'ods_count': len(ids_ods),
                'total': 0
            })

        if dry_run:
            return jsonify({
                'status': 'success',
                'dry_run': True,
                'xdr_count': len(ids_xdr),
                'ods_count': len(ids_ods),
                'total': len(all_ids),
                'detection_ids': all_ids
            })

        batch_size = MAX_DETECT_LIMIT
        success_count = 0
        failure_count = 0

        for i in range(0, len(all_ids), batch_size):
            batch = all_ids[i:i + batch_size]
            response = falcon_detect.update_Alerts_by_ids(
                ids=batch,
                status=status,
                comment=comment
            )
            if response.get('status_code') in [200, 202]:
                success_count += len(batch)
            else:
                failure_count += len(batch)

        return jsonify({
            'status': 'success',
            'xdr_count': len(ids_xdr),
            'ods_count': len(ids_ods),
            'total': len(all_ids),
            'success': success_count,
            'failure': failure_count
        })

    except Exception as e:
        logger.exception("Error closing by hash")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/hash-summary', methods=['GET'])
def hash_summary():
    """Get summary of SHA256 hashes in detections"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        filter_string = request.args.get('filter', 'status:"new"')
        requested_limit = int(request.args.get('limit', MAX_DETECT_LIMIT))
        limit = min(requested_limit, MAX_DETECT_LIMIT)

        falcon_detect = Alerts(auth_object=falcon_auth)

        response = falcon_detect.query_alerts(filter=filter_string, limit=limit)

        if response.get('status_code') != 200:
            logger.error(f"hash_summary query failed: {response}")
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        if not detection_ids:
            return jsonify({'hashes': [], 'total_detections': 0, 'unique_hashes': 0})

        details_response = falcon_detect.get_alerts(ids=detection_ids)
        if details_response.get('status_code') != 200:
            logger.error(f"hash_summary details failed: {details_response}")
            return jsonify({'error': 'Failed to get detection details'}), 500

        hash_counts = {}

        for det in details_response['body'].get('resources', []):
            entities = det.get('entities', {}) or {}
            entity_values = det.get('entity_values', {}) or {}

            sha256_list = entities.get('sha256', []) or []
            sha256_values = entity_values.get('sha256s', []) or []
            all_hashes = set(sha256_list + sha256_values)

            for h in all_hashes:
                if h:
                    hash_counts[h] = hash_counts.get(h, 0) + 1

        hash_list = [
            {'hash': h, 'count': c}
            for h, c in sorted(hash_counts.items(), key=lambda x: x[1], reverse=True)
        ]

        return jsonify({
            'hashes': hash_list,
            'total_detections': len(detection_ids),
            'unique_hashes': len(hash_list)
        })

    except Exception as e:
        logger.exception("Error getting hash summary")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/advanced-search', methods=['POST'])
def advanced_search():
    """Advanced detection search with FQL filter"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        filter_string = data.get('filter', '')
        requested_limit = int(data.get('limit', MAX_DETECT_LIMIT))
        limit = min(requested_limit, MAX_DETECT_LIMIT)
        offset = int(data.get('offset', 0))

        falcon_detect = Alerts(auth_object=falcon_auth)

        response = falcon_detect.query_alerts(
            filter=filter_string,
            limit=limit,
            offset=offset
        )

        if response.get('status_code') != 200:
            logger.error(f"advanced_search query failed: {response}")
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        if not detection_ids:
            return jsonify({'detections': [], 'count': 0})

        details_response = falcon_detect.get_alerts(ids=detection_ids)
        if details_response.get('status_code') != 200:
            logger.error(f"advanced_search details failed: {details_response}")
            return jsonify({'error': 'Failed to get detection details'}), 500

        detections = []
        for det in details_response['body'].get('resources', []):
            behaviors = det.get('behaviors', [{}])
            first_behavior = behaviors[0] if behaviors else {}
            device = det.get('device', {}) or {}

            detections.append({
                'id': det.get('detection_id') or det.get('id'),
                'name': first_behavior.get('tactic', 'Unknown'),
                'severity': (det.get('max_severity_displayname') or '').lower(),
                'status': det.get('status'),
                'timestamp': det.get('created_timestamp'),
                'host': device.get('hostname', 'Unknown'),
                'behavior': first_behavior.get('tactic', 'Unknown')
            })

        return jsonify({
            'detections': detections,
            'count': len(detections)
        })

    except Exception as e:
        logger.exception("Error in advanced search")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/create-exclusion', methods=['POST'])
def create_ioc_exclusion():
    """Create IOC exclusion (allow/whitelist)"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401

    try:
        data = request.json or {}
        hash_value = data.get('hash')
        hash_type = data.get('type', 'sha256')
        description = data.get('description', '')
        applied_globally = data.get('applied_globally', True)
        host_groups = data.get('host_groups', [])
        severity = data.get('severity', 'informational')

        if not hash_value or not description:
            return jsonify({'error': 'Hash and description required'}), 400

        falcon_ioc = IOC(auth_object=falcon_auth)

        indicator = {
            'type': hash_type,
            'value': hash_value,
            'policy': 'none',
            'description': description,
            'severity': severity,
            'applied_globally': applied_globally
        }

        if host_groups and not applied_globally:
            indicator['host_groups'] = host_groups

        response = falcon_ioc.indicator_create(body={'indicators': [indicator]})

        if response.get('status_code') in [200, 201]:
            resources = response['body'].get('resources', [])
            indicator_resp = resources[0] if resources else {}
            return jsonify({
                'status': 'success',
                'message': 'IOC exclusion created successfully',
                'indicator': indicator_resp
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to create exclusion',
                'errors': response['body'].get('errors', 'Unknown error')
            }), 500

    except Exception as e:
        logger.exception("Error creating IOC exclusion")
        return jsonify({'error': str(e)}), 500

# ---------------------------------------------------------------------------
# ROOT
# ---------------------------------------------------------------------------

@app.route('/')
def index():
    """Simple index endpoint so hitting the root works"""
    return jsonify({
        'status': 'CrowdStrike Falcon API Backend',
        'version': '1.0',
        'endpoints': [rule.rule for rule in app.url_map.iter_rules()]
    })


if __name__ == '__main__':
    app.run(debug=True, port=5003, host='0.0.0.0')