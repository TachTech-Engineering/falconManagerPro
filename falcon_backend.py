from flask import Flask, jsonify, request, send_file
from flask_cors import CORS
from falconpy import Alerts, Hosts, Incidents, EventStreams, OAuth2, IOC, Intel
from datetime import datetime, timedelta
import logging
import json
import threading
import time
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Global authentication and state
falcon_auth = None
saved_views = {}
playbooks = {}

# ============================================================================
# AUTHENTICATION
# ============================================================================

@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Authenticate with CrowdStrike Falcon API"""
    global falcon_auth
    
    data = request.json
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    base_url = data.get('base_url', 'https://api.crowdstrike.com')
    
    try:
        falcon_auth = OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )
        
        token = falcon_auth.token()
        if token:
            return jsonify({'status': 'success', 'message': 'Authentication successful'})
        else:
            return jsonify({'status': 'error', 'message': 'Authentication failed'}), 401
            
    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

# ============================================================================
# DETECTIONS - Full Management
# ============================================================================

@app.route('/api/detections', methods=['GET'])
def get_detections():
    """Fetch detections from CrowdStrike Falcon"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        print("DEBUG: Starting get_detections")
        falcon_detect = Alerts(auth_object=falcon_auth)
        print("DEBUG: Created Alerts object")
        
        severity = request.args.get('severity', None)
        status = request.args.get('status', None)
        hours = int(request.args.get('hours', 24))
        
        time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(hours=hours)).isoformat()}Z'"
        filters = [time_filter]
        
        if severity:
            filters.append(f"max_severity:'{severity}'")
        if status:
            filters.append(f"status:'{status}'")
        
        filter_string = '+'.join(filters)
        print(f"DEBUG: Filter string: {filter_string}")
        
        response = falcon_detect.query_alerts(
            filter=filter_string,
            limit=100,
            sort='created_timestamp.desc'
        )
        print(f"DEBUG: query_Alerts response code: {response['status_code']}")
        
        if response['status_code'] != 200:
            print(f"DEBUG: Query failed with body: {response['body']}")
            return jsonify({'error': 'Failed to query detections'}), 500
        
        detection_ids = response['body']['resources']
        print(f"DEBUG: Found {len(detection_ids)} detection IDs")
        
        if not detection_ids:
            return jsonify({'detections': []})
        
        details_response = falcon_detect.get_alerts(ids=detection_ids)
        print(f"DEBUG: get_detect_summaries response code: {details_response['status_code']}")
        
        if details_response['status_code'] != 200:
            print(f"DEBUG: Get summaries failed with body: {details_response['body']}")
            return jsonify({'error': 'Failed to get detection details'}), 500
        
        detections = []
        for det in details_response['body']['resources']:
            detections.append({
                'id': det.get('detection_id'),
                'name': det.get('behaviors', [{}])[0].get('tactic', 'Unknown'),
                'severity': det.get('max_severity_displayname', '').lower(),
                'status': det.get('status'),
                'timestamp': det.get('created_timestamp'),
                'host': det.get('device', {}).get('hostname', 'Unknown'),
                'host_id': det.get('device', {}).get('device_id'),
                'behavior': det.get('behaviors', [{}])[0].get('tactic', 'Unknown'),
                'description': det.get('behaviors', [{}])[0].get('description', ''),
                'assigned_to': det.get('assigned_to_name', 'Unassigned')
            })
        
        print(f"DEBUG: Successfully processed {len(detections)} detections")
        return jsonify({'detections': detections})
        
    except Exception as e:
        print(f"ERROR DETAILS: {e}")
        import traceback
        traceback.print_exc()
        logger.error(f"Error fetching detections: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/<detection_id>/status', methods=['PATCH'])
def update_detection_status(detection_id):
    """Update detection status with comment and assignment"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        new_status = data.get('status')
        comment = data.get('comment', '')
        assigned_to = data.get('assigned_to', None)
        
        if not new_status:
            return jsonify({'error': 'Status is required'}), 400
        
        falcon_detect = Alerts(auth_object=falcon_auth)
        
        response = falcon_detect.update_Alerts_by_ids(
            ids=[detection_id],
            status=new_status,
            assigned_to_uuid=assigned_to,
            comment=comment
        )
        
        if response['status_code'] not in [200, 202]:
            return jsonify({'error': 'Failed to update detection status'}), 500
        
        return jsonify({
            'status': 'success',
            'message': f'Detection updated to {new_status}',
            'detection_id': detection_id
        })
        
    except Exception as e:
        logger.error(f"Error updating detection: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/bulk-update', methods=['POST'])
def bulk_update_detections():
    """Bulk update multiple detections"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
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
        
        if response['status_code'] not in [200, 202]:
            return jsonify({'error': 'Failed to bulk update'}), 500
        
        return jsonify({
            'status': 'success',
            'message': f'{len(detection_ids)} detections updated',
            'count': len(detection_ids)
        })
        
    except Exception as e:
        logger.error(f"Error in bulk update: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# IOC MANAGEMENT
# ============================================================================

@app.route('/api/iocs', methods=['GET'])
def get_iocs():
    """Get custom IOCs"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        falcon_ioc = IOC(auth_object=falcon_auth)
        
        ioc_type = request.args.get('type', None)
        
        filters = []
        if ioc_type:
            filters.append(f"type:'{ioc_type}'")
        
        filter_string = '+'.join(filters) if filters else None
        
        response = falcon_ioc.indicator_search(
            filter=filter_string,
            limit=100
        )
        
        if response['status_code'] != 200:
            return jsonify({'error': 'Failed to query IOCs'}), 500
        
        ioc_ids = response['body']['resources']
        
        if not ioc_ids:
            return jsonify({'iocs': []})
        
        details_response = falcon_ioc.indicator_get(ids=ioc_ids)
        
        if details_response['status_code'] != 200:
            return jsonify({'error': 'Failed to get IOC details'}), 500
        
        return jsonify({'iocs': details_response['body']['resources']})
        
    except Exception as e:
        logger.error(f"Error fetching IOCs: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs', methods=['POST'])
def create_ioc():
    """Create new IOC"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        
        falcon_ioc = IOC(auth_object=falcon_auth)
        
        response = falcon_ioc.indicator_create(
            body={
                "indicators": [{
                    "type": data.get('type'),
                    "value": data.get('value'),
                    "policy": data.get('policy', 'detect'),
                    "description": data.get('description', ''),
                    "severity": data.get('severity', 'medium'),
                    "tags": data.get('tags', [])
                }]
            }
        )
        
        if response['status_code'] not in [200, 201]:
            return jsonify({'error': 'Failed to create IOC'}), 500
        
        return jsonify({
            'status': 'success',
            'message': 'IOC created successfully',
            'ioc': response['body']['resources'][0]
        })
        
    except Exception as e:
        logger.error(f"Error creating IOC: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/<ioc_id>', methods=['DELETE'])
def delete_ioc(ioc_id):
    """Delete IOC"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        falcon_ioc = IOC(auth_object=falcon_auth)
        
        response = falcon_ioc.indicator_delete(ids=[ioc_id])
        
        if response['status_code'] != 200:
            return jsonify({'error': 'Failed to delete IOC'}), 500
        
        return jsonify({
            'status': 'success',
            'message': 'IOC deleted successfully'
        })
        
    except Exception as e:
        logger.error(f"Error deleting IOC: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# AUTOMATED RESPONSE / PLAYBOOKS
# ============================================================================

@app.route('/api/playbooks', methods=['GET'])
def get_playbooks():
    """Get all automated response playbooks"""
    return jsonify({'playbooks': list(playbooks.values())})


@app.route('/api/playbooks', methods=['POST'])
def create_playbook():
    """Create automated response playbook"""
    data = request.json
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
        data = request.json
        target_id = data.get('target_id')
        
        results = []
        
        for action in playbook['actions']:
            if action['type'] == 'contain_host':
                falcon_hosts = Hosts(auth_object=falcon_auth)
                response = falcon_hosts.perform_action(
                    action_name='contain',
                    ids=[target_id]
                )
                results.append({
                    'action': 'contain_host',
                    'status': 'success' if response['status_code'] == 200 else 'failed'
                })
            
            elif action['type'] == 'close_detection':
                falcon_detect = Alerts(auth_object=falcon_auth)
                response = falcon_detect.update_detections(
                    ids=[target_id],
                    status='false_positive',
                    comment=f"Auto-closed by playbook: {playbook['name']}"
                )
                results.append({
                    'action': 'close_detection',
                    'status': 'success' if response['status_code'] in [200, 202] else 'failed'
                })
        
        return jsonify({
            'status': 'success',
            'results': results
        })
        
    except Exception as e:
        logger.error(f"Error executing playbook: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# CUSTOM DASHBOARDS / SAVED VIEWS
# ============================================================================

@app.route('/api/views', methods=['GET'])
def get_saved_views():
    """Get all saved dashboard views"""
    return jsonify({'views': list(saved_views.values())})


@app.route('/api/views', methods=['POST'])
def create_saved_view():
    """Create a saved dashboard view"""
    data = request.json
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

# ============================================================================
# REPORT GENERATION
# ============================================================================

@app.route('/api/reports/generate', methods=['POST'])
def generate_report():
    """Generate PDF report"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        report_type = data.get('type', 'detections')
        time_range = data.get('time_range', 24)
        
        # Create PDF
        buffer = BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=letter)
        styles = getSampleStyleSheet()
        story = []
        
        # Title
        title = Paragraph(f"<b>CrowdStrike Falcon {report_type.title()} Report</b>", styles['Title'])
        story.append(title)
        story.append(Spacer(1, 12))
        
        # Metadata
        metadata = Paragraph(f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>Time Range: Last {time_range} hours", styles['Normal'])
        story.append(metadata)
        story.append(Spacer(1, 12))
        
        # Fetch data based on report type
        if report_type == 'detections':
            falcon_detect = Alerts(auth_object=falcon_auth)
            time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(hours=time_range)).isoformat()}Z'"
            
            response = falcon_detect.query_Alerts(filter=time_filter, limit=100)
            detection_ids = response['body']['resources']
            
            if detection_ids:
                details = falcon_detect.get_detect_summaries(ids=detection_ids)
                
                # Create table
                table_data = [['Detection ID', 'Severity', 'Status', 'Host', 'Created']]
                
                for det in details['body']['resources'][:20]:
                    table_data.append([
                        det.get('detection_id', '')[:20] + '...',
                        det.get('max_severity_displayname', ''),
                        det.get('status', ''),
                        det.get('device', {}).get('hostname', ''),
                        det.get('created_timestamp', '')[:19]
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
        logger.error(f"Error generating report: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# REAL-TIME EVENT STREAMING via POLLING
# ============================================================================

@app.route('/api/events/recent', methods=['GET'])
def get_recent_events():
    """Get recent events (used for polling)"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        falcon_detect = Alerts(auth_object=falcon_auth)
        
        # Get detections from last 5 minutes
        time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(minutes=5)).isoformat()}Z'"
        response = falcon_detect.query_detections(filter=time_filter, limit=10)
        
        if response['status_code'] == 200:
            return jsonify({
                'status': 'success',
                'detection_ids': response['body']['resources']
            })
        
        return jsonify({'status': 'success', 'detection_ids': []})
        
    except Exception as e:
        logger.error(f"Error fetching recent events: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# HOSTS MANAGEMENT
# ============================================================================

@app.route('/api/hosts', methods=['GET'])
def get_hosts():
    """Fetch hosts from CrowdStrike Falcon"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        print("DEBUG: Starting get_hosts")
        falcon_hosts = Hosts(auth_object=falcon_auth)
        print("DEBUG: Created Hosts object")
        
        status = request.args.get('status', None)
        limit = int(request.args.get('limit', 100))
        
        filter_string = None
        if status:
            filter_string = f"status:'{status}'"
        
        print(f"DEBUG: Querying hosts with filter: {filter_string}, limit: {limit}")
        response = falcon_hosts.query_devices(
            filter=filter_string,
            limit=limit,
            sort='last_seen.desc'
        )
        
        print(f"DEBUG: query_devices response code: {response['status_code']}")
        
        if response['status_code'] != 200:
            print(f"DEBUG: Query hosts failed with body: {response['body']}")
            return jsonify({'error': 'Failed to query hosts'}), 500
        
        host_ids = response['body']['resources']
        print(f"DEBUG: Found {len(host_ids)} host IDs")
        
        if not host_ids:
            return jsonify({'hosts': []})
        
        details_response = falcon_hosts.get_device_details(ids=host_ids)
        print(f"DEBUG: get_device_details response code: {details_response['status_code']}")
        
        if details_response['status_code'] != 200:
            print(f"DEBUG: Get host details failed with body: {details_response['body']}")
            return jsonify({'error': 'Failed to get host details'}), 500
        
        hosts = []
        for host in details_response['body']['resources']:
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
        
        print(f"DEBUG: Successfully processed {len(hosts)} hosts")
        return jsonify({'hosts': hosts})
        
    except Exception as e:
        print(f"ERROR DETAILS: {e}")
        import traceback
        traceback.print_exc()
        logger.error(f"Error fetching hosts: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/hosts/<host_id>/contain', methods=['POST'])
def contain_host(host_id):
    """Contain (isolate) a host"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        falcon_hosts = Hosts(auth_object=falcon_auth)
        response = falcon_hosts.perform_action(
            action_name='contain',
            ids=[host_id]
        )
        
        if response['status_code'] != 200:
            return jsonify({'error': 'Failed to contain host'}), 500
        
        return jsonify({'status': 'success', 'message': 'Host contained'})
        
    except Exception as e:
        logger.error(f"Error containing host: {str(e)}")
        return jsonify({'error': str(e)}), 500


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
        logger.error(f"Health check error: {str(e)}")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# ADVANCED DETECTION OPERATIONS
# ============================================================================

@app.route('/api/detections/close-by-hash', methods=['POST'])
def close_by_hash():
    """Close all detections with a specific SHA256 hash"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        hash_value = data.get('hash')
        comment = data.get('comment', 'Closed via hash - approved by SOC')
        status = data.get('status', 'closed')
        dry_run = data.get('dry_run', False)
        
        if not hash_value:
            return jsonify({'error': 'Hash value required'}), 400
        
        falcon_detect = Alerts(auth_object=falcon_auth)
        
        # Search for hash in both XDR and ODS detections
        filter_xdr = f'entities.sha256:"{hash_value}"'
        filter_ods = f'sha256:"{hash_value}"'
        
        ids_xdr = []
        ids_ods = []
        
        # Query XDR detections
        response_xdr = falcon_detect.query_Alerts(filter=filter_xdr, limit=10000)
        if response_xdr['status_code'] == 200:
            ids_xdr = response_xdr['body']['resources']
        
        # Query ODS detections
        response_ods = falcon_detect.query_Alerts(filter=filter_ods, limit=10000)
        if response_ods['status_code'] == 200:
            ids_ods = response_ods['body']['resources']
        
        # Combine and deduplicate
        all_ids = list(set(ids_xdr + ids_ods))
        
        if not all_ids:
            return jsonify({
                'status': 'success',
                'message': 'No detections found with this hash',
                'xdr_count': 0,
                'ods_count': 0,
                'total': 0
            })
        
        # Dry run mode
        if dry_run:
            return jsonify({
                'status': 'success',
                'dry_run': True,
                'xdr_count': len(ids_xdr),
                'ods_count': len(ids_ods),
                'total': len(all_ids),
                'detection_ids': all_ids
            })
        
        # Bulk update in batches
        batch_size = 1000
        success_count = 0
        failure_count = 0
        
        for i in range(0, len(all_ids), batch_size):
            batch = all_ids[i:i + batch_size]
            response = falcon_detect.update_Alerts_by_ids(
                ids=batch,
                status=status,
                comment=comment
            )
            
            if response['status_code'] in [200, 202]:
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
        logger.error(f"Error closing by hash: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/hash-summary', methods=['GET'])
def hash_summary():
    """Get summary of SHA256 hashes in detections"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        filter_string = request.args.get('filter', 'status:"new"')
        limit = int(request.args.get('limit', 10000))
        
        falcon_detect = Alerts(auth_object=falcon_auth)
        
        # Query detections
        response = falcon_detect.query_Alerts(filter=filter_string, limit=limit)
        
        if response['status_code'] != 200:
            return jsonify({'error': 'Failed to query detections'}), 500
        
        detection_ids = response['body']['resources']
        
        if not detection_ids:
            return jsonify({'hashes': [], 'total_detections': 0})
        
        # Get detection details
        details_response = falcon_detect.get_detect_summaries(ids=detection_ids)
        
        if details_response['status_code'] != 200:
            return jsonify({'error': 'Failed to get detection details'}), 500
        
        # Count hashes
        hash_counts = {}
        
        for det in details_response['body']['resources']:
            # Get SHA256 values from various fields
            sha256_list = det.get('entities', {}).get('sha256', [])
            sha256_values = det.get('entity_values', {}).get('sha256s', [])
            all_hashes = set(sha256_list + sha256_values)
            
            for hash_val in all_hashes:
                if hash_val:
                    hash_counts[hash_val] = hash_counts.get(hash_val, 0) + 1
        
        # Convert to sorted list
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
        logger.error(f"Error getting hash summary: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/detections/advanced-search', methods=['POST'])
def advanced_search():
    """Advanced detection search with FQL filter"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        filter_string = data.get('filter', '')
        limit = int(data.get('limit', 100))
        offset = int(data.get('offset', 0))
        
        falcon_detect = Alerts(auth_object=falcon_auth)
        
        # Query detections
        response = falcon_detect.query_Alerts(
            filter=filter_string,
            limit=limit,
            offset=offset
        )
        
        if response['status_code'] != 200:
            return jsonify({'error': 'Failed to query detections'}), 500
        
        detection_ids = response['body']['resources']
        
        if not detection_ids:
            return jsonify({'detections': [], 'count': 0})
        
        # Get detection details
        details_response = falcon_detect.get_detect_summaries(ids=detection_ids)
        
        if details_response['status_code'] != 200:
            return jsonify({'error': 'Failed to get detection details'}), 500
        
        detections = []
        for det in details_response['body']['resources']:
            detections.append({
                'id': det.get('detection_id'),
                'name': det.get('behaviors', [{}])[0].get('tactic', 'Unknown'),
                'severity': det.get('max_severity_displayname', '').lower(),
                'status': det.get('status'),
                'timestamp': det.get('created_timestamp'),
                'host': det.get('device', {}).get('hostname', 'Unknown'),
                'behavior': det.get('behaviors', [{}])[0].get('tactic', 'Unknown')
            })
        
        return jsonify({
            'detections': detections,
            'count': len(detections)
        })
        
    except Exception as e:
        logger.error(f"Error in advanced search: {str(e)}")
        return jsonify({'error': str(e)}), 500


@app.route('/api/iocs/create-exclusion', methods=['POST'])
def create_ioc_exclusion():
    """Create IOC exclusion (allow/whitelist)"""
    if not falcon_auth:
        return jsonify({'error': 'Not authenticated'}), 401
    
    try:
        data = request.json
        hash_value = data.get('hash')
        hash_type = data.get('type', 'sha256')
        description = data.get('description', '')
        applied_globally = data.get('applied_globally', True)
        host_groups = data.get('host_groups', [])
        severity = data.get('severity', 'informational')
        
        if not hash_value or not description:
            return jsonify({'error': 'Hash and description required'}), 400
        
        falcon_ioc = IOC(auth_object=falcon_auth)
        
        # Prepare indicator body
        indicator_body = {
            'indicators': [{
                'type': hash_type,
                'value': hash_value,
                'policy': 'none',  # 'none' means allow/exclude
                'description': description,
                'severity': severity,
                'applied_globally': applied_globally
            }]
        }
        
        # Add host groups if not global
        if host_groups and not applied_globally:
            indicator_body['indicators'][0]['host_groups'] = host_groups
        
        # Create indicator
        response = falcon_ioc.indicator_create(body=indicator_body)
        
        if response['status_code'] in [200, 201]:
            return jsonify({
                'status': 'success',
                'message': 'IOC exclusion created successfully',
                'indicator': response['body']['resources'][0] if 'resources' in response['body'] else {}
            })
        else:
            return jsonify({
                'status': 'error',
                'message': 'Failed to create exclusion',
                'errors': response['body'].get('errors', 'Unknown error')
            }), 500
        
    except Exception as e:
        logger.error(f"Error creating IOC exclusion: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/')
def index():
    """Root endpoint for testing"""
    return jsonify({
        'status': 'CrowdStrike Falcon API Backend',
        'version': '1.0',
        'endpoints': [rule.rule for rule in app.url_map.iter_rules()]
    })

if __name__ == '__main__':
    # Change port if 5000 is in use
    app.run(debug=True, port=5003, host='0.0.0.0')