# Load environment variables from .env file
from dotenv import load_dotenv
load_dotenv()

from flask import Flask, jsonify, request, send_file, g
from flask_cors import CORS
from falconpy import Alerts, Hosts, Incidents, EventStreams, OAuth2, IOC, Intel, RealTimeResponse
from datetime import datetime, timedelta
import logging
import time
import requests
from io import BytesIO
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib import colors
import csv
import os
import json
from apscheduler.schedulers.background import BackgroundScheduler
import atexit
import uuid
import hashlib
import secrets
from functools import wraps
import smtplib
from email.message import EmailMessage

# Import database components
try:
    from database import db, tenant_dao, playbook_dao, execution_dao, ioc_dao
    DB_ENABLED = True
    logging.info("✅ Database module loaded successfully")
except Exception as e:
    DB_ENABLED = False
    logging.warning(f"⚠️ Database not available: {e}")

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})


# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Session storage (in-memory for now, use Redis in production)
active_sessions = {}  # session_token -> {tenant_id, created_at, expires_at}

# Cache configuration
CACHE_TIMEOUT = 300
tenant_caches = {}  # tenant_id -> {last_fetch, hosts}

# API limits
MAX_DETECT_LIMIT = 5000
MAX_DETECT_DETAIL_BATCH = 1000
MAX_HOST_DETAIL_BATCH = 5000
MAX_IOC_LIMIT = 2000

EMAIL_ENABLED = True  # toggle to disable email sending
SMTP_HOST = os.environ.get('SMTP_HOST', 'smtp-relay.gmail.com')
SMTP_PORT = int(os.environ.get('SMTP_PORT', '587'))
SMTP_FROM = os.environ.get('SMTP_FROM', 'reports@tachtech.net')
SMTP_USE_TLS = True

# Auto-trigger configuration
AUTO_TRIGGER_ENABLED = True
AUTO_TRIGGER_INTERVAL = 60
LOOKBACK_WINDOW = 5
processed_detections = {}  # tenant_id -> set of detection_ids

# Initialize scheduler
scheduler = BackgroundScheduler()
scheduler.start()

# ============================================================================
# SESSION & TENANT MANAGEMENT
# ============================================================================

def generate_session_token():
    """Generate a secure random session token"""
    return secrets.token_urlsafe(32)

def get_tenant_by_credentials(client_id, client_secret, base_url):
    """Get or create tenant based on CrowdStrike credentials"""
    if not DB_ENABLED:
        return None
    
    tenant_hash = hashlib.sha256(client_id.encode()).hexdigest()[:16]
    domain = f"tenant_{tenant_hash}"
    
    try:
        tenant = tenant_dao.get_by_domain(domain)
        
        if tenant:
            if (tenant['crowdstrike_client_id'] != client_id or 
                tenant['crowdstrike_client_secret'] != client_secret or
                tenant['crowdstrike_base_url'] != base_url):
                tenant = tenant_dao.update(tenant['id'], {
                    'crowdstrike_client_id': client_id,
                    'crowdstrike_client_secret': client_secret,
                    'crowdstrike_base_url': base_url
                })
            return tenant
        else:
            tenant = tenant_dao.create({
                'name': f'Tenant {tenant_hash}',
                'domain': domain,
                'api_key': generate_session_token(),
                'crowdstrike_client_id': client_id,
                'crowdstrike_client_secret': client_secret,
                'crowdstrike_base_url': base_url,
                'plan': 'enterprise'
            })
            logger.info(f"✅ Created new tenant: {tenant['id']}")
            
            # Initialize processed detections for new tenant
            processed_detections[tenant['id']] = set()
            
            return tenant
            
    except Exception as e:
        logger.error(f"Error managing tenant: {e}")
        return None

def require_session(f):
    """Decorator that validates session token and loads tenant"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        session_token = request.headers.get('X-Session-Token') or request.headers.get('Authorization', '').replace('Bearer ', '')
        
        if not session_token:
            return jsonify({'error': 'Authentication required'}), 401
        
        session = active_sessions.get(session_token)
        if not session:
            return jsonify({'error': 'Invalid or expired session'}), 401
        
        if datetime.utcnow() > session['expires_at']:
            del active_sessions[session_token]
            return jsonify({'error': 'Session expired'}), 401
        
        tenant = tenant_dao.get_by_id(session['tenant_id'])
        if not tenant:
            return jsonify({'error': 'Tenant not found'}), 401
        
        g.tenant = tenant
        g.tenant_id = tenant['id']
        g.session_token = session_token
        
        try:
            g.falcon_auth = OAuth2(
                client_id=tenant['crowdstrike_client_id'],
                client_secret=tenant['crowdstrike_client_secret'],
                base_url=tenant['crowdstrike_base_url']
            )
        except Exception as e:
            logger.error(f"Error creating OAuth for tenant: {e}")
            return jsonify({'error': 'Failed to create CrowdStrike session'}), 500
        
        return f(*args, **kwargs)
    
    return decorated_function

# ============================================================================
# AUTO-TRIGGER SYSTEM
# ============================================================================

def auto_execute_playbooks():
    """
    Background job that checks for new detections across all tenants
    and executes matching playbooks
    """
    if not AUTO_TRIGGER_ENABLED or not DB_ENABLED:
        return
    
    try:
        logger.info("🤖 Auto-trigger: Checking detections across all tenants...")
        
        # Get all active tenants with valid sessions
        active_tenants = {}
        for session_token, session_data in list(active_sessions.items()):
            if datetime.utcnow() <= session_data['expires_at']:
                tenant_id = session_data['tenant_id']
                if tenant_id not in active_tenants:
                    tenant = tenant_dao.get_by_id(tenant_id)
                    if tenant:
                        active_tenants[tenant_id] = tenant
        
        if not active_tenants:
            logger.debug("No active tenant sessions for auto-trigger")
            return
        
        # Process each tenant
        for tenant_id, tenant in active_tenants.items():
            try:
                process_tenant_auto_triggers(tenant)
            except Exception as e:
                logger.error(f"Error processing auto-triggers for tenant {tenant_id}: {e}")
        
    except Exception as e:
        logger.error(f"Error in auto_execute_playbooks: {e}")


def process_tenant_auto_triggers(tenant):
    """Process auto-triggers for a specific tenant"""
    tenant_id = tenant['id']
    
    # Initialize processed detections set for tenant if not exists
    if tenant_id not in processed_detections:
        processed_detections[tenant_id] = set()
    
    # Create auth for this tenant
    try:
        falcon_auth = OAuth2(
            client_id=tenant['crowdstrike_client_id'],
            client_secret=tenant['crowdstrike_client_secret'],
            base_url=tenant['crowdstrike_base_url']
        )
    except Exception as e:
        logger.error(f"Failed to create auth for tenant {tenant_id}: {e}")
        return
    
    # Get active playbooks with automatic triggers
    auto_playbooks = playbook_dao.get_all(tenant_id)
    auto_playbooks = [
        pb for pb in auto_playbooks 
        if pb.get('enabled') and pb.get('trigger') != 'manual'
    ]
    
    if not auto_playbooks:
        logger.debug(f"No auto-trigger playbooks for tenant {tenant_id}")
        return
    
    # Fetch recent detections
    falcon_detect = Alerts(auth_object=falcon_auth)
    
    lookback_time = datetime.utcnow() - timedelta(minutes=LOOKBACK_WINDOW)
    time_filter = f"created_timestamp:>'{lookback_time.isoformat()}Z'"
    
    response = falcon_detect.query_alerts(
        filter=time_filter,
        limit=100,
        sort='created_timestamp.desc'
    )
    
    if response.get('status_code') != 200:
        logger.error(f"Failed to fetch detections for tenant {tenant_id}")
        return
    
    detection_ids = response['body'].get('resources', []) or []
    
    if not detection_ids:
        logger.debug(f"No new detections for tenant {tenant_id}")
        return
    
    # Get detection details
    details_response = falcon_detect.get_alerts(ids=detection_ids)
    
    if details_response.get('status_code') != 200:
        logger.error(f"Failed to get detection details for tenant {tenant_id}")
        return
    
    detections = details_response['body'].get('resources', [])
    
    # Process each detection
    for detection in detections:
        detection_id = detection.get('detection_id') or detection.get('id')
        
        # Skip if already processed
        if detection_id in processed_detections[tenant_id]:
            continue
        
        # Mark as processed
        processed_detections[tenant_id].add(detection_id)
        
        # Extract detection details
        severity = (detection.get('max_severity_displayname') or '').lower()
        behaviors = detection.get('behaviors', [{}])
        first_behavior = behaviors[0] if behaviors else {}
        tactic = (first_behavior.get('tactic') or '').lower()
        technique = (first_behavior.get('technique') or '').lower()
        scenario = (first_behavior.get('scenario') or '').lower()
        device = detection.get('device', {}) or {}
        host_id = device.get('device_id')
        
        # Check for ransomware indicators
        ransomware_keywords = [
            'ransomware', 'ransom', 'cryptolocker', 'wannacry', 
            'ryuk', 'revil', 'lockbit', 'encryption', 'crypto'
        ]
        is_ransomware = any(
            keyword in tactic or 
            keyword in technique or 
            keyword in scenario or
            keyword in (detection.get('description') or '').lower()
            for keyword in ransomware_keywords
        )
        
        # Match against playbooks
        for playbook in auto_playbooks:
            trigger = playbook.get('trigger')
            should_execute = False
            target_type = 'detection'
            target_id = detection_id
            
            # Check trigger conditions
            if trigger == 'critical_detection' and severity == 'critical':
                should_execute = True
                logger.info(f"🔴 Critical detection matched for tenant {tenant_id}: {detection_id}")
                
            elif trigger == 'high_detection' and severity == 'high':
                should_execute = True
                logger.info(f"🟠 High severity detection matched for tenant {tenant_id}: {detection_id}")
                
            elif trigger == 'ransomware' and is_ransomware:
                should_execute = True
                logger.info(f"🚨 RANSOMWARE detection matched for tenant {tenant_id}: {detection_id}")
                
                # For ransomware, use host as target if available
                if host_id:
                    target_type = 'host'
                    target_id = host_id
            
            # Execute playbook
            if should_execute:
                try:
                    logger.info(f"⚡ Auto-executing playbook '{playbook['name']}' for tenant {tenant_id}")
                    
                    execute_playbook_actions(
                        tenant_id=tenant_id,
                        playbook=playbook,
                        target_type=target_type,
                        target_id=target_id,
                        falcon_auth=falcon_auth,
                        trigger_type='auto',
                        detection_id=detection_id
                    )
                    
                except Exception as e:
                    logger.error(f"Error auto-executing playbook {playbook['id']}: {e}")
    
    # Clean up old processed detections (keep last 1000 per tenant)
    if len(processed_detections[tenant_id]) > 1000:
        processed_detections[tenant_id] = set(list(processed_detections[tenant_id])[-1000:])


def execute_playbook_actions(tenant_id, playbook, target_type, target_id, 
                             falcon_auth, trigger_type='manual', detection_id=None):
    """
    Execute playbook actions and record in database
    """
    start_time = datetime.utcnow()
    playbook_id = playbook['id']
    
    results = []
    successful = 0
    failed = 0
    skipped = 0
    
    for action in playbook.get('actions', []):
        action_type = action.get('type')
        action_params = action.get('params', {})
        
        action_result = {
            'action': action_type,
            'status': 'skipped',
            'detail': '',
            'timestamp': datetime.utcnow().isoformat()
        }
        
        try:
            # Execute action based on type
            if action_type == 'contain_host' and target_type == 'host':
                falcon_hosts = Hosts(auth_object=falcon_auth)
                response = falcon_hosts.perform_action(action_name='contain', ids=[target_id])
                if response.get('status_code') in [200, 201, 202]:
                    action_result['status'] = 'success'
                    action_result['detail'] = 'Host contained successfully'
                    successful += 1
                else:
                    action_result['status'] = 'failed'
                    action_result['detail'] = str(response)
                    failed += 1
            
            elif action_type == 'close_detection' and target_type == 'detection':
                falcon_detect = Alerts(auth_object=falcon_auth)
                response = falcon_detect.update_Alerts_by_ids(
                    ids=[target_id],
                    status='false_positive',
                    comment=f"Auto-closed by playbook: {playbook['name']}"
                )
                if response.get('status_code') in [200, 202]:
                    action_result['status'] = 'success'
                    action_result['detail'] = 'Detection closed'
                    successful += 1
                else:
                    action_result['status'] = 'failed'
                    failed += 1
            
            elif action_type == 'kill_process' and target_type == 'host':
                process = action_params.get('process')
                if process:
                    rtr = RealTimeResponse(auth_object=falcon_auth)
                    init_resp = rtr.batch_init_sessions(body={"host_ids": [target_id], "queue_offline": False})
                    if init_resp.get("status_code") in (200, 201):
                        batch_id = init_resp.get("body", {}).get("batch_id")
                        cmd_resp = rtr.batch_active_responder_command(
                            base_command="kill",
                            batch_id=batch_id,
                            command_string=f'process={process}',
                            host_ids=[target_id]
                        )
                        if cmd_resp.get("status_code") in (200, 201):
                            action_result['status'] = 'success'
                            action_result['detail'] = f'Process {process} terminated'
                            successful += 1
                        else:
                            action_result['status'] = 'failed'
                            failed += 1
            
            elif action_type == 'delete_file' and target_type == 'host':
                file_path = action_params.get('path')
                if file_path:
                    rtr = RealTimeResponse(auth_object=falcon_auth)
                    init_resp = rtr.batch_init_sessions(body={"host_ids": [target_id], "queue_offline": False})
                    if init_resp.get("status_code") in (200, 201):
                        batch_id = init_resp.get("body", {}).get("batch_id")
                        cmd_resp = rtr.batch_active_responder_command(
                            base_command="rm",
                            batch_id=batch_id,
                            command_string=f'path="{file_path}"',
                            host_ids=[target_id]
                        )
                        if cmd_resp.get("status_code") in (200, 201):
                            action_result['status'] = 'success'
                            action_result['detail'] = f'File deleted: {file_path}'
                            successful += 1
                        else:
                            action_result['status'] = 'failed'
                            failed += 1
            
            elif action_type == 'create_ioc' and target_type == 'detection':
                falcon_detect = Alerts(auth_object=falcon_auth)
                det_resp = falcon_detect.get_alerts(ids=[target_id])
                if det_resp.get('status_code') == 200:
                    resources = det_resp['body'].get('resources', [])
                    if resources:
                        det = resources[0]
                        entities = det.get('entities', {}) or {}
                        sha256_list = entities.get('sha256', [])
                        if sha256_list:
                            ioc_value = sha256_list[0]
                            ioc_type = action_params.get('ioc_type', 'sha256')
                            severity_ioc = action_params.get('severity', 'medium')
                            
                            falcon_ioc = IOC(auth_object=falcon_auth)
                            body = {"indicators": [{
                                "type": ioc_type,
                                "value": ioc_value,
                                "action": "detect",
                                "description": f"Auto-created by playbook: {playbook['name']}",
                                "severity": severity_ioc,
                                "applied_globally": True
                            }]}
                            ioc_resp = falcon_ioc.indicator_create(body=body)
                            if ioc_resp.get('status_code') in [200, 201]:
                                action_result['status'] = 'success'
                                action_result['detail'] = f'IOC created: {ioc_value[:16]}...'
                                successful += 1
                            else:
                                action_result['status'] = 'failed'
                                failed += 1
            
            elif action_type == 'tag_detection' and target_type == 'detection':
                tags_str = action_params.get('tags', '')
                tags = [t.strip() for t in tags_str.split(',') if t.strip()]
                falcon_detect = Alerts(auth_object=falcon_auth)
                comment = f"Tags: {', '.join(tags)} (via playbook: {playbook['name']})"
                response = falcon_detect.update_Alerts_by_ids(ids=[target_id], comment=comment)
                if response.get('status_code') in [200, 202]:
                    action_result['status'] = 'success'
                    action_result['detail'] = f'Tagged with: {", ".join(tags)}'
                    successful += 1
                else:
                    action_result['status'] = 'failed'
                    failed += 1
            
            elif action_type == 'assign_to_user' and target_type == 'detection':
                user_uuid = action_params.get('user_uuid')
                if user_uuid:
                    falcon_detect = Alerts(auth_object=falcon_auth)
                    response = falcon_detect.update_Alerts_by_ids(
                        ids=[target_id],
                        assigned_to_uuid=user_uuid,
                        comment=f"Auto-assigned by playbook: {playbook['name']}"
                    )
                    if response.get('status_code') in [200, 202]:
                        action_result['status'] = 'success'
                        action_result['detail'] = f'Assigned to user: {user_uuid[:8]}...'
                        successful += 1
                    else:
                        action_result['status'] = 'failed'
                        failed += 1
            
            elif action_type == 'run_rtr_script' and target_type == 'host':
                script_name = action_params.get('script_name')
                arguments = action_params.get('arguments', '')
                if script_name:
                    rtr = RealTimeResponse(auth_object=falcon_auth)
                    init_resp = rtr.batch_init_sessions(body={"host_ids": [target_id], "queue_offline": False})
                    if init_resp.get("status_code") in (200, 201):
                        batch_id = init_resp.get("body", {}).get("batch_id")
                        cmd_string = f'CloudFile="{script_name}"'
                        if arguments:
                            cmd_string += f' CommandLine="{arguments}"'
                        cmd_resp = rtr.batch_admin_cmd(
                            base_command="runscript",
                            batch_id=batch_id,
                            command_string=cmd_string,
                            host_ids=[target_id],
                            timeout=120
                        )
                        if cmd_resp.get("status_code") in (200, 201):
                            action_result['status'] = 'success'
                            action_result['detail'] = f'Script executed: {script_name}'
                            successful += 1
                        else:
                            action_result['status'] = 'failed'
                            failed += 1
            
            else:
                skipped += 1
                
        except Exception as e:
            action_result['status'] = 'failed'
            action_result['detail'] = str(e)
            failed += 1
            logger.error(f"Error executing action {action_type}: {e}")
        
        results.append(action_result)
    
    # Calculate duration
    duration_ms = int((datetime.utcnow() - start_time).total_seconds() * 1000)
    
    # Record execution in database
    try:
        execution_dao.create(tenant_id, {
            'playbook_id': playbook_id,
            'trigger_type': trigger_type,
            'target_type': target_type,
            'target_id': target_id,
            'total_actions': len(results),
            'successful_actions': successful,
            'failed_actions': failed,
            'skipped_actions': skipped,
            'status': 'completed',
            'results': results
        })
        
        # Update playbook execution count
        playbook_dao.record_execution(tenant_id, playbook_id)
        
        logger.info(
            f"✅ Playbook '{playbook['name']}' execution complete: "
            f"{successful}/{len(results)} actions succeeded"
        )
    except Exception as e:
        logger.error(f"Error recording playbook execution: {e}")


# Schedule the auto-trigger job
scheduler.add_job(
    func=auto_execute_playbooks,
    trigger="interval",
    seconds=AUTO_TRIGGER_INTERVAL,
    id='auto_trigger_playbooks',
    name='Auto-execute playbooks for matching detections',
    replace_existing=True
)

logger.info(f"🤖 Auto-trigger system initialized (checking every {AUTO_TRIGGER_INTERVAL}s)")

# ============================================================================
# HELPER FUNCTIONS
# ============================================================================

def _generate_pdf_report(
    report_type,
    title,
    time_range,
    detections,
    hosts,
    iocs,
    severity_counts,
    status_counts,
    include_summary,
    include_charts,
    total_detections=None,
    total_hosts=None,
    total_iocs=None,
):
    """Generate a comprehensive PDF report"""
    buffer = BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=letter)
    styles = getSampleStyleSheet()
    story = []

    story.append(Paragraph(f"<b>{title}</b>", styles['Title']))
    story.append(Spacer(1, 12))

    metadata = Paragraph(
        f"Generated: {datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S UTC')}<br/>"
        f"Report Type: {report_type.replace('_', ' ').title()}<br/>"
        f"Time Range: Last {time_range} hours",
        styles['Normal']
    )
    story.append(metadata)
    story.append(Spacer(1, 20))

    if include_summary:
        story.append(Paragraph("<b>Executive Summary</b>", styles['Heading1']))
        story.append(Spacer(1, 12))

        # Use true totals if provided, otherwise fall back to len()
        td = total_detections if total_detections is not None else len(detections)
        th = total_hosts if total_hosts is not None else len(hosts)
        ti = total_iocs if total_iocs is not None else len(iocs)

        summary_data = [
            ['Metric', 'Count'],
            ['Total Detections', str(td)],
            ['Critical Severity', str(severity_counts.get('critical', 0))],
            ['High Severity', str(severity_counts.get('high', 0))],
            ['Total Hosts', str(th)],
            ['Custom IOCs', str(ti)],
        ]

        summary_table = Table(summary_data)
        summary_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        story.append(summary_table)
        story.append(Spacer(1, 20))

    if detections and report_type in ['executive', 'detailed', 'timeline']:
        story.append(Paragraph("<b>Recent Detections</b>", styles['Heading1']))
        story.append(Spacer(1, 12))

        det_data = [['Severity', 'Status', 'Host', 'Tactic', 'Timestamp']]
        for det in detections[:25]:
            det_data.append([
                det['severity'][:10],
                det['status'][:12],
                det['host'][:20],
                det.get('tactic', det.get('behavior', 'Unknown'))[:20],
                det['timestamp'][:19] if det['timestamp'] else 'N/A'
            ])

        det_table = Table(det_data)
        det_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        story.append(det_table)
        story.append(Spacer(1, 20))

    if hosts and (report_type == 'host_inventory' or len(hosts) > 0):
        story.append(Paragraph("<b>Host Inventory</b>", styles['Heading1']))
        story.append(Spacer(1, 12))

        host_data = [['Hostname', 'IP Address', 'OS', 'Status', 'Agent Version']]
        for host in hosts[:25]:
            host_data.append([
                host['hostname'][:20],
                host['ip'][:15],
                host['os'][:25],
                host['status'][:10],
                host['agent_version'][:15]
            ])

        host_table = Table(host_data)
        host_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 8),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        story.append(host_table)
        story.append(Spacer(1, 20))

    if iocs and (report_type == 'ioc_intelligence' or len(iocs) > 0):
        story.append(Paragraph("<b>Indicators of Compromise</b>", styles['Heading1']))
        story.append(Spacer(1, 12))

        ioc_data = [['Type', 'Value', 'Severity', 'Policy', 'Description']]
        for ioc in iocs[:25]:
            value = ioc['value']
            desc = ioc.get('description', '')
            ioc_data.append([
                ioc['type'][:10],
                value[:30] + '...' if len(value) > 30 else value,
                ioc['severity'][:10],
                ioc.get('policy', ioc.get('action', 'detect'))[:10],
                desc[:30] + '...' if len(desc) > 30 else desc
            ])

        ioc_table = Table(ioc_data)
        ioc_table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, -1), 7),
            ('GRID', (0, 0), (-1, -1), 1, colors.black),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige)
        ]))
        story.append(ioc_table)

    doc.build(story)
    buffer.seek(0)
    return buffer


def _generate_csv_report(detections, hosts, iocs, report_type):
    """Generate CSV report"""
    buffer = BytesIO()
    buffer.write(b'\xef\xbb\xbf')

    import io
    text_wrapper = io.TextIOWrapper(buffer, encoding='utf-8', newline='')
    writer = csv.writer(text_wrapper)

    if report_type in ['executive', 'detailed', 'timeline'] and detections:
        writer.writerow(['Detection ID', 'Severity', 'Status', 'Host', 'Tactic', 'Technique', 'Timestamp', 'Description'])
        for det in detections:
            writer.writerow([
                det['id'],
                det['severity'],
                det['status'],
                det['host'],
                det.get('tactic', det.get('behavior', 'Unknown')),
                det.get('technique', ''),
                det['timestamp'],
                det.get('description', '')[:100]
            ])
    elif report_type == 'host_inventory' and hosts:
        writer.writerow(['Hostname', 'IP Address', 'Operating System', 'Status', 'Agent Version', 'Last Seen'])
        for host in hosts:
            writer.writerow([
                host['hostname'],
                host['ip'],
                host['os'],
                host['status'],
                host['agent_version'],
                host.get('lastSeen', host.get('last_seen', ''))
            ])
    elif report_type == 'ioc_intelligence' and iocs:
        writer.writerow(['Type', 'Value', 'Severity', 'Policy', 'Description'])
        for ioc in iocs:
            writer.writerow([
                ioc['type'],
                ioc['value'],
                ioc['severity'],
                ioc.get('policy', ioc.get('action', 'detect')),
                ioc.get('description', '')
            ])

    text_wrapper.flush()
    buffer.seek(0)
    return buffer

def _get_rtr():
    """Helper to build RTR client"""
    if not hasattr(g, 'falcon_auth'):
        raise RuntimeError("Not authenticated")
    return RealTimeResponse(auth_object=g.falcon_auth)

def _extract_rtr_output(cmd_resp, device_id):
    """Extract RTR command output"""
    body = cmd_resp.get("body", {})
    combined = body.get("combined", {})
    resources = combined.get("resources", {})
    device_output = resources.get(device_id, {})
    
    return {
        'stdout': device_output.get('stdout', ''),
        'stderr': device_output.get('stderr', ''),
        'complete': device_output.get('complete', False),
        'aid': device_output.get('aid', device_id),
        'session_id': device_output.get('session_id', ''),
        'task_id': device_output.get('task_id', '')
    }

# ============================================================================
# AUTHENTICATION
# ============================================================================

@app.route('/api/auth', methods=['POST'])
def authenticate():
    """Authenticate and create tenant automatically"""
    data = request.json or {}
    client_id = data.get('client_id')
    client_secret = data.get('client_secret')
    base_url = data.get('base_url', 'https://api.crowdstrike.com')

    if not client_id or not client_secret:
        return jsonify({'status': 'error', 'message': 'client_id and client_secret are required'}), 400

    try:
        test_auth = OAuth2(
            client_id=client_id,
            client_secret=client_secret,
            base_url=base_url
        )

        token = test_auth.token()
        if not token:
            return jsonify({'status': 'error', 'message': 'Invalid CrowdStrike credentials'}), 401

        if DB_ENABLED:
            tenant = get_tenant_by_credentials(client_id, client_secret, base_url)
            
            if not tenant:
                return jsonify({'status': 'error', 'message': 'Failed to create tenant'}), 500
            
            session_token = generate_session_token()
            active_sessions[session_token] = {
                'tenant_id': tenant['id'],
                'created_at': datetime.utcnow(),
                'expires_at': datetime.utcnow() + timedelta(hours=24)
            }
            
            logger.info(f"✅ Authenticated tenant: {tenant['name']} ({tenant['id']})")
            
            return jsonify({
                'status': 'success',
                'message': 'Authentication successful',
                'session_token': session_token,
                'tenant': {
                    'id': tenant['id'],
                    'name': tenant['name'],
                    'plan': tenant['plan']
                }
            })
        else:
            return jsonify({'status': 'error', 'message': 'Database not available'}), 500

    except Exception as e:
        logger.error(f"Authentication error: {str(e)}")
        return jsonify({'status': 'error', 'message': str(e)}), 500

@app.route('/api/session/info', methods=['GET'])
@require_session
def get_session_info():
    """Get current session information"""
    session_data = active_sessions.get(g.session_token)
    
    return jsonify({
        'tenant': {
            'id': g.tenant['id'],
            'name': g.tenant['name'],
            'plan': g.tenant['plan']
        },
        'session': {
            'created_at': session_data['created_at'].isoformat(),
            'expires_at': session_data['expires_at'].isoformat()
        }
    })

@app.route('/api/session/logout', methods=['POST'])
def logout():
    """Logout and clear session"""
    session_token = request.headers.get('X-Session-Token')
    
    if session_token and session_token in active_sessions:
        del active_sessions[session_token]
    
    return jsonify({'status': 'success', 'message': 'Logged out'})

# ============================================================================
# DETECTIONS
# ============================================================================

@app.route('/api/detections', methods=['GET'])
@require_session
def get_detections():
    """Fetch detections from CrowdStrike"""
    try:
        falcon_detect = Alerts(auth_object=g.falcon_auth)
        
        severity = request.args.get('severity')
        status = request.args.get('status')
        hours = int(request.args.get('hours', 24))
        hours = min(hours, 720)

        time_filter = f"created_timestamp:>'{(datetime.utcnow() - timedelta(hours=hours)).isoformat()}Z'"
        filters = [time_filter]

        if severity:
            filters.append(f"max_severity_displayname:'{severity}'")
        if status:
            filters.append(f"status:'{status}'")

        filter_string = "+".join(filters)
        
        response = falcon_detect.query_alerts(
            filter=filter_string,
            limit=MAX_DETECT_LIMIT,
            sort='created_timestamp.desc'
        )

        if response.get('status_code') != 200:
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        if not detection_ids:
            return jsonify({'detections': []})

        def get_severity(det, is_first=False):
            """Extract severity from detection, checking multiple possible fields"""
            if is_first:
                logger.info(f"=== DETECTION FIELD DEBUG (Tenant: {g.tenant_id}) ===")
                logger.info(f"Available keys: {list(det.keys())}")
                logger.info(f"max_severity: {det.get('max_severity')}")
                logger.info(f"max_severity_displayname: {det.get('max_severity_displayname')}")
                logger.info(f"severity: {det.get('severity')}")
                logger.info(f"severity_name: {det.get('severity_name')}")
                behaviors = det.get('behaviors', [])
                if behaviors:
                    logger.info(f"First behavior keys: {list(behaviors[0].keys())}")
                    logger.info(f"First behavior severity: {behaviors[0].get('severity')}")
                logger.info(f"=== END DEBUG ===")

            # Try max_severity_displayname first (most common)
            if det.get('max_severity_displayname'):
                return det['max_severity_displayname'].lower()

            # Try severity_name
            if det.get('severity_name'):
                return det['severity_name'].lower()

            # Try numeric max_severity
            severity_num = det.get('max_severity')
            if severity_num is not None:
                severity_map = {
                    10: 'informational',
                    20: 'low',
                    30: 'medium',
                    40: 'high',
                    50: 'critical',
                    70: 'critical'
                }
                mapped = severity_map.get(severity_num, 'unknown')
                if mapped != 'unknown':
                    return mapped

            # Try severity field (string or int)
            severity_val = det.get('severity')
            if severity_val:
                if isinstance(severity_val, str):
                    return severity_val.lower()
                elif isinstance(severity_val, int):
                    severity_map = {
                        10: 'informational',
                        20: 'low',
                        30: 'medium',
                        40: 'high',
                        50: 'critical',
                        70: 'critical'
                    }
                    mapped = severity_map.get(severity_val, 'unknown')
                    if mapped != 'unknown':
                        return mapped

            # Try behavior severity as last resort
            behaviors = det.get('behaviors', [])
            if behaviors:
                first_behavior = behaviors[0]

                if first_behavior.get('severity_name'):
                    return first_behavior['severity_name'].lower()

                behavior_severity = first_behavior.get('severity')
                if behavior_severity is not None:
                    if isinstance(behavior_severity, str):
                        return behavior_severity.lower()
                    elif isinstance(behavior_severity, int):
                        severity_map = {
                            10: 'informational',
                            20: 'low',
                            30: 'medium',
                            40: 'high',
                            50: 'critical',
                            70: 'critical'
                        }
                        mapped = severity_map.get(behavior_severity, 'unknown')
                        if mapped != 'unknown':
                            return mapped

            if is_first:
                logger.warning(f"Could not determine severity for detection {det.get('detection_id') or det.get('id')}")
            return 'unknown'

        detections = []
        is_first_detection = True

        for i in range(0, len(detection_ids), MAX_DETECT_DETAIL_BATCH):
            batch_ids = detection_ids[i:i + MAX_DETECT_DETAIL_BATCH]
            details_response = falcon_detect.get_alerts(ids=batch_ids)

            if details_response.get('status_code') != 200:
                continue

            for det in details_response['body'].get('resources', []):
                behaviors = det.get('behaviors', [{}])
                first_behavior = behaviors[0] if behaviors else {}
                device = det.get('device', {}) or {}

                # Use comprehensive severity extraction
                severity_value = get_severity(det, is_first=is_first_detection)
                is_first_detection = False

                # Detect if detection has hashes
                entities = det.get('entities', {}) or {}
                entity_values = det.get('entity_values', {}) or {}
                has_sha256 = bool(entities.get('sha256') or entity_values.get('sha256s'))
                has_md5 = bool(entities.get('md5') or entity_values.get('md5s'))
                has_sha1 = bool(entities.get('sha1') or entity_values.get('sha1s'))
                has_hash = has_sha256 or has_md5 or has_sha1

                detections.append({
                    'id': det.get('detection_id') or det.get('id'),
                    'name': first_behavior.get('tactic', 'Unknown'),
                    'severity': severity_value,
                    'status': det.get('status'),
                    'timestamp': det.get('created_timestamp'),
                    'host': device.get('hostname', 'Unknown'),
                    'host_id': device.get('device_id'),
                    'behavior': first_behavior.get('tactic', 'Unknown'),
                    'description': first_behavior.get('description', ''),
                    'assigned_to': det.get('assigned_to_name', 'Unassigned'),
                    'has_hash': has_hash,
                    'technique': first_behavior.get('technique', ''),
                    'scenario': first_behavior.get('scenario', '')
                })

        return jsonify({'detections': detections})

    except Exception as e:
        logger.exception("Error fetching detections")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detections/<detection_id>/status', methods=['PATCH'])
@require_session
def update_detection_status(detection_id):
    """Update detection status"""
    try:
        data = request.json or {}
        new_status = data.get('status')
        comment = data.get('comment', '')
        assigned_to = data.get('assigned_to')

        if not new_status:
            return jsonify({'error': 'Status is required'}), 400

        falcon_detect = Alerts(auth_object=g.falcon_auth)
        response = falcon_detect.update_Alerts_by_ids(
            ids=[detection_id],
            status=new_status,
            assigned_to_uuid=assigned_to,
            comment=comment
        )

        if response.get('status_code') not in [200, 202]:
            return jsonify({'error': 'Failed to update detection'}), 500

        return jsonify({
            'status': 'success',
            'message': f'Detection updated to {new_status}',
            'detection_id': detection_id
        })

    except Exception as e:
        logger.exception("Error updating detection")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detections/bulk-update', methods=['POST'])
@require_session
def bulk_update_detections():
    """Bulk update detections"""
    try:
        data = request.json or {}
        detection_ids = data.get('detection_ids', [])
        new_status = data.get('status')
        comment = data.get('comment', '')

        if not detection_ids or not new_status:
            return jsonify({'error': 'detection_ids and status required'}), 400

        falcon_detect = Alerts(auth_object=g.falcon_auth)
        response = falcon_detect.update_Alerts_by_ids(
            ids=detection_ids,
            status=new_status,
            comment=comment
        )

        if response.get('status_code') not in [200, 202]:
            return jsonify({'error': 'Failed to bulk update'}), 500

        return jsonify({
            'status': 'success',
            'message': f'{len(detection_ids)} detections updated',
            'count': len(detection_ids)
        })

    except Exception as e:
        logger.exception("Error in bulk update")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detections/close-by-hash', methods=['POST'])
@require_session
def close_by_hash():
    """Close all detections with a specific SHA256 hash"""
    try:
        data = request.json or {}
        hash_value = data.get('hash')
        comment = data.get('comment', 'Closed via hash - approved by SOC')
        status = data.get('status', 'closed')
        dry_run = data.get('dry_run', False)

        if not hash_value:
            return jsonify({'error': 'Hash value required'}), 400

        falcon_detect = Alerts(auth_object=g.falcon_auth)
        filter_string = f'entities.sha256:"{hash_value}"'

        response = falcon_detect.query_alerts(filter=filter_string, limit=MAX_DETECT_LIMIT)
        
        if response.get('status_code') != 200:
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []

        if not detection_ids:
            return jsonify({
                'status': 'success',
                'message': 'No detections found with this hash',
                'total': 0
            })

        if dry_run:
            return jsonify({
                'status': 'success',
                'dry_run': True,
                'total': len(detection_ids),
                'detection_ids': detection_ids
            })

        update_response = falcon_detect.update_Alerts_by_ids(
            ids=detection_ids,
            status=status,
            comment=comment
        )
        
        if update_response.get('status_code') in [200, 202]:
            return jsonify({
                'status': 'success',
                'total': len(detection_ids),
                'success': len(detection_ids)
            })
        else:
            return jsonify({'error': 'Failed to update detections'}), 500

    except Exception as e:
        logger.exception("Error closing by hash")
        return jsonify({'error': str(e)}), 500

@app.route('/api/detections/hash-summary', methods=['GET'])
@require_session
def hash_summary():
    """Get summary of SHA256 hashes in detections"""
    try:
        filter_string = request.args.get('filter', 'status:"new"')
        limit = min(int(request.args.get('limit', MAX_DETECT_LIMIT)), MAX_DETECT_LIMIT)

        falcon_detect = Alerts(auth_object=g.falcon_auth)
        response = falcon_detect.query_alerts(filter=filter_string, limit=limit)

        if response.get('status_code') != 200:
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        if not detection_ids:
            return jsonify({'hashes': [], 'total_detections': 0, 'unique_hashes': 0})

        hash_counts = {}
        for i in range(0, len(detection_ids), MAX_DETECT_DETAIL_BATCH):
            batch_ids = detection_ids[i:i + MAX_DETECT_DETAIL_BATCH]
            details_response = falcon_detect.get_alerts(ids=batch_ids)

            if details_response.get('status_code') != 200:
                continue

            for det in details_response['body'].get('resources', []):
                entities = det.get('entities', {}) or {}
                sha256_list = entities.get('sha256', []) or []

                for h in sha256_list:
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
@require_session
def advanced_search():
    """Advanced detection search with FQL filter"""
    try:
        data = request.json or {}
        filter_string = data.get('filter', '')
        limit = min(int(data.get('limit', MAX_DETECT_LIMIT)), MAX_DETECT_LIMIT)
        offset = int(data.get('offset', 0))

        falcon_detect = Alerts(auth_object=g.falcon_auth)
        response = falcon_detect.query_alerts(
            filter=filter_string,
            limit=limit,
            offset=offset
        )

        if response.get('status_code') != 200:
            return jsonify({'error': 'Failed to query detections'}), 500

        detection_ids = response['body'].get('resources', []) or []
        if not detection_ids:
            return jsonify({'detections': [], 'count': 0})

        details_response = falcon_detect.get_alerts(ids=detection_ids)
        if details_response.get('status_code') != 200:
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

@app.route('/api/events/recent', methods=['GET'])
@require_session
def get_recent_events():
    """Get recent detections for polling"""
    try:
        falcon_detect = Alerts(auth_object=g.falcon_auth)
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

# ============================================================================
# HOSTS
# ============================================================================

@app.route('/api/hosts', methods=['GET'])
@require_session
def get_hosts():
    """Fetch hosts from CrowdStrike with per-tenant caching"""
    try:
        force_refresh = request.args.get('force_refresh', 'false').lower() == 'true'
        status_filter = request.args.get('status')
        requested_limit = int(request.args.get('limit', 100000))

        current_time = time.time()
        tenant_id = g.tenant_id
        
        # Check tenant-specific cache
        if tenant_id in tenant_caches and not force_refresh:
            cache = tenant_caches[tenant_id]
            cache_age = current_time - cache['last_fetch']
            
            if cache_age < CACHE_TIMEOUT:
                hosts_to_return = cache['hosts']
                if status_filter:
                    hosts_to_return = [h for h in hosts_to_return if h.get('status') == status_filter]

                return jsonify({
                    'hosts': hosts_to_return[:requested_limit],
                    'total': len(hosts_to_return),
                    'cached': True,
                    'cache_age': int(cache_age)
                })

        falcon_hosts = Hosts(auth_object=g.falcon_auth)
        
        filter_string = None
        if status_filter:
            filter_string = f"status:'{status_filter}'"

        all_hosts = []
        batch_size = 5000
        offset_token = None
        batch_number = 0

        while True:
            batch_number += 1
            
            query_params = {
                'filter': filter_string,
                'limit': batch_size,
                'sort': 'last_seen.desc'
            }

            if offset_token:
                query_params['offset'] = offset_token

            response = falcon_hosts.query_devices_by_filter_scroll(**query_params)

            if response.get('status_code') != 200:
                if batch_number == 1:
                    return jsonify({'error': 'Failed to query hosts'}), 500
                break

            body = response.get('body', {})
            host_ids = body.get('resources', []) or []

            if not host_ids:
                break

            meta = body.get('meta', {})
            pagination = meta.get('pagination', {})
            offset_token = pagination.get('offset')

            details_response = falcon_hosts.get_device_details(ids=host_ids)

            if details_response.get('status_code') != 200:
                break

            for host in details_response['body'].get('resources', []):
                platform_name = host.get('platform_name', '')
                os_version = host.get('os_version', '')
                os_str = f"{platform_name} {os_version}".strip() if platform_name and os_version else platform_name or 'Unknown'

                host_status = host.get('status', 'unknown')

                all_hosts.append({
                    'id': host.get('device_id', ''),
                    'hostname': host.get('hostname', 'Unknown'),
                    'ip': host.get('local_ip', 'N/A'),
                    'os': os_str,
                    'status': host_status,
                    'lastSeen': host.get('last_seen', ''),
                    'agent_version': host.get('agent_version', ''),
                    'platform': platform_name,
                    'contained': host_status == 'contained'
                })

            if not offset_token or batch_number >= 20:
                break

            time.sleep(0.1)

        # Update tenant-specific cache
        tenant_caches[tenant_id] = {
            'last_fetch': current_time,
            'hosts': all_hosts
        }

        hosts_to_return = all_hosts
        if status_filter:
            hosts_to_return = [h for h in hosts_to_return if h.get('status') == status_filter]

        return jsonify({
            'hosts': hosts_to_return[:requested_limit],
            'total': len(hosts_to_return),
            'cached': False,
            'cache_age': 0
        })

    except Exception as e:
        logger.exception("Error fetching hosts")
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/contain', methods=['POST'])
@require_session
def contain_host(device_id):
    """Network-contain a host"""
    try:
        falcon_hosts = Hosts(auth_object=g.falcon_auth)
        resp = falcon_hosts.perform_action(action_name="contain", ids=[device_id])

        if resp.get("status_code") not in (200, 201, 202):
            return jsonify({'error': 'Failed to contain host'}), 500

        return jsonify({'status': 'success', 'action': 'contain', 'device_id': device_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/lift-containment', methods=['POST'])
@require_session
def lift_containment(device_id):
    """Release host from containment"""
    try:
        falcon_hosts = Hosts(auth_object=g.falcon_auth)
        resp = falcon_hosts.perform_action(action_name="lift_containment", ids=[device_id])

        if resp.get("status_code") not in (200, 201, 202):
            return jsonify({'error': 'Failed to lift containment'}), 500

        return jsonify({'status': 'success', 'action': 'lift_containment', 'device_id': device_id})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# IOCs
# ============================================================================

@app.route('/api/iocs', methods=['GET'])
@require_session
def get_iocs():
    """Get IOCs for tenant - merges database and CrowdStrike IOCs"""
    try:
        all_iocs = []
        
        # First, try to get IOCs from database
        if DB_ENABLED:
            try:
                db_iocs = ioc_dao.get_all(g.tenant_id)
                logger.info(f"Retrieved {len(db_iocs)} IOCs from database for tenant {g.tenant_id}")
                
                for ioc in db_iocs:
                    all_iocs.append({
                        'id': ioc['id'],
                        'type': ioc['ioc_type'],
                        'value': ioc['ioc_value'],
                        'policy': ioc['policy'],
                        'severity': (ioc.get('severity') or 'medium').lower(),
                        'description': ioc.get('description', ''),
                        'tags': ioc.get('tags', []),
                        'created_on': ioc.get('created_at'),
                        'modified_on': ioc.get('updated_at'),
                        'source': 'database'
                    })
            except Exception as e:
                logger.error(f"Error fetching IOCs from database: {e}")
        
        # Also fetch IOCs from CrowdStrike
        try:
            logger.info(f"Fetching IOCs from CrowdStrike API for tenant {g.tenant_id}")
            falcon_ioc = IOC(auth_object=g.falcon_auth)
            ioc_type = request.args.get('type')

            filters = []
            if ioc_type:
                filters.append(f"type:'{ioc_type}'")

            filter_string = "+".join(filters) if filters else None

            response = falcon_ioc.indicator_search(
                filter=filter_string,
                limit=MAX_IOC_LIMIT
            )

            if response.get('status_code') == 200:
                ioc_ids = response['body'].get('resources', []) or []
                logger.info(f"Found {len(ioc_ids)} IOC IDs from CrowdStrike")
                
                if ioc_ids:
                    details_response = falcon_ioc.indicator_get(ids=ioc_ids)
                    if details_response.get('status_code') == 200:
                        for ioc in details_response['body'].get('resources', []):
                            all_iocs.append({
                                'id': ioc.get('id'),
                                'type': ioc.get('type'),
                                'value': ioc.get('value'),
                                'policy': ioc.get('action'),
                                'severity': (ioc.get('severity') or 'medium').lower(),
                                'description': ioc.get('description', ''),
                                'tags': ioc.get('tags', []),
                                'created_on': ioc.get('created_on'),
                                'modified_on': ioc.get('modified_on'),
                                'source': 'crowdstrike'
                            })
                        logger.info(f"Successfully retrieved {len(details_response['body'].get('resources', []))} IOCs from CrowdStrike")
                    else:
                        logger.error(f"IOC details fetch failed: {details_response.get('body')}")
                else:
                    logger.info("No IOCs found in CrowdStrike")
            else:
                logger.error(f"IOC search failed with status {response.get('status_code')}: {response.get('body')}")
        except Exception as e:
            logger.error(f"Error fetching IOCs from CrowdStrike: {e}")

        logger.info(f"Total IOCs returned: {len(all_iocs)} (database + CrowdStrike)")
        return jsonify({'iocs': all_iocs})

    except Exception as e:
        logger.exception("Error in get_iocs")
        return jsonify({'error': str(e), 'iocs': []}), 500

@app.route('/api/iocs', methods=['POST'])
@require_session
def create_ioc():
    """Create new IOC"""
    try:
        data = request.json or {}
        
        if DB_ENABLED:
            ioc = ioc_dao.create(g.tenant_id, {
                'ioc_type': data.get('type'),
                'ioc_value': data.get('value'),
                'policy': data.get('policy', 'detect'),
                'severity': data.get('severity', 'medium'),
                'description': data.get('description', ''),
                'tags': data.get('tags', [])
            })
            
            return jsonify({
                'status': 'success',
                'message': 'IOC created successfully',
                'ioc': ioc
            })
        
        # Fallback to CrowdStrike
        falcon_ioc = IOC(auth_object=g.falcon_auth)

        body = {
            "indicators": [{
                "type": data.get('type'),
                "value": data.get('value'),
                "action": data.get('policy', 'detect'),
                "description": data.get('description', ''),
                "severity": data.get('severity', 'medium'),
                "tags": data.get('tags', []),
                "applied_globally": True
            }]
        }

        response = falcon_ioc.indicator_create(body=body)

        if response.get('status_code') not in [200, 201]:
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
@require_session
def delete_ioc(ioc_id):
    """Delete IOC"""
    try:
        if DB_ENABLED:
            success = ioc_dao.delete(g.tenant_id, ioc_id)
            if success:
                return jsonify({
                    'status': 'success',
                    'message': 'IOC deleted successfully',
                    'deleted_id': ioc_id
                })
        
        # Fallback to CrowdStrike
        falcon_ioc = IOC(auth_object=g.falcon_auth)
        response = falcon_ioc.indicator_delete(ids=[ioc_id])

        if response.get('status_code') != 200:
            return jsonify({'error': 'Failed to delete IOC'}), 500

        return jsonify({
            'status': 'success',
            'message': 'IOC deleted successfully',
            'deleted_id': ioc_id
        })

    except Exception as e:
        logger.exception("Error deleting IOC")
        return jsonify({'error': str(e)}), 500

@app.route('/api/iocs/create-exclusion', methods=['POST'])
@require_session
def create_ioc_exclusion():
    """Create IOC exclusion"""
    try:
        data = request.json or {}
        hash_value = data.get('hash')
        hash_type = data.get('type', 'sha256')
        description = data.get('description', '')

        if not hash_value or not description:
            return jsonify({'error': 'Hash and description required'}), 400

        falcon_ioc = IOC(auth_object=g.falcon_auth)

        indicator = {
            'type': hash_type,
            'value': hash_value,
            'action': 'no_action',
            'description': description,
            'severity': 'informational',
            'applied_globally': data.get('applied_globally', True)
        }

        response = falcon_ioc.indicator_create(body={'indicators': [indicator]})

        if response.get('status_code') in [200, 201]:
            return jsonify({
                'status': 'success',
                'message': 'IOC exclusion created successfully'
            })
        else:
            return jsonify({'error': 'Failed to create exclusion'}), 500

    except Exception as e:
        logger.exception("Error creating IOC exclusion")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# PLAYBOOKS
# ============================================================================

@app.route('/api/playbooks', methods=['GET'])
@require_session
def get_playbooks():
    """Get all playbooks for tenant"""
    try:
        if DB_ENABLED:
            playbooks_list = playbook_dao.get_all(g.tenant_id)
            return jsonify({'playbooks': playbooks_list})
        else:
            return jsonify({'playbooks': []})
    except Exception as e:
        logger.exception("Error fetching playbooks")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks', methods=['POST'])
@require_session
def create_playbook():
    """Create playbook"""
    try:
        data = request.json or {}
        
        if DB_ENABLED:
            playbook = playbook_dao.create(g.tenant_id, {
                'name': data.get('name', 'New Playbook'),
                'description': data.get('description', ''),
                'trigger': data.get('trigger', 'manual'),
                'actions': data.get('actions', []),
                'enabled': data.get('enabled', True)
            })
            
            return jsonify({
                'status': 'success',
                'playbook': playbook
            })
        else:
            return jsonify({'error': 'Database not available'}), 500

    except Exception as e:
        logger.exception("Error creating playbook")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/<playbook_id>', methods=['PUT'])
@require_session
def update_playbook(playbook_id):
    """Update playbook"""
    try:
        data = request.json or {}
        
        if DB_ENABLED:
            playbook = playbook_dao.update(g.tenant_id, playbook_id, data)
            
            if not playbook:
                return jsonify({'error': 'Playbook not found'}), 404
            
            return jsonify({
                'status': 'success',
                'playbook': playbook
            })
        else:
            return jsonify({'error': 'Database not available'}), 500

    except Exception as e:
        logger.exception("Error updating playbook")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/<playbook_id>', methods=['DELETE'])
@require_session
def delete_playbook(playbook_id):
    """Delete playbook"""
    try:
        if DB_ENABLED:
            success = playbook_dao.delete(g.tenant_id, playbook_id)
            if not success:
                return jsonify({'error': 'Playbook not found'}), 404
            
            return jsonify({
                'status': 'success',
                'message': 'Playbook deleted'
            })
        else:
            return jsonify({'error': 'Database not available'}), 500

    except Exception as e:
        logger.exception("Error deleting playbook")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/<playbook_id>/execute', methods=['POST'])
@require_session
def execute_playbook(playbook_id):
    """Execute playbook manually"""
    try:
        if DB_ENABLED:
            playbook = playbook_dao.get_by_id(g.tenant_id, playbook_id)
        else:
            return jsonify({'error': 'Database not available'}), 500
            
        if not playbook:
            return jsonify({'error': 'Playbook not found'}), 404
        
        data = request.json or {}
        target_id = data.get('target_id')
        target_type = data.get('target_type', 'detection')

        if not target_id:
            return jsonify({'error': 'target_id is required'}), 400

        # Execute using shared function
        execute_playbook_actions(
            tenant_id=g.tenant_id,
            playbook=playbook,
            target_type=target_type,
            target_id=target_id,
            falcon_auth=g.falcon_auth,
            trigger_type='manual'
        )

        # Get recent execution result
        executions = execution_dao.get_recent(g.tenant_id, limit=1)
        latest = executions[0] if executions else {}

        return jsonify({
            'status': 'success',
            'execution': latest
        })

    except Exception as e:
        logger.exception("Error executing playbook")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/<playbook_id>/history', methods=['GET'])
@require_session
def get_playbook_history(playbook_id):
    """Get execution history for specific playbook"""
    try:
        limit = int(request.args.get('limit', 50))
        
        if DB_ENABLED:
            all_executions = execution_dao.get_recent(g.tenant_id, limit=200)
            playbook_executions = [
                ex for ex in all_executions 
                if ex.get('playbook_id') == playbook_id
            ]
            
            return jsonify({
                'history': playbook_executions[:limit],
                'total': len(playbook_executions)
            })
        else:
            return jsonify({'history': [], 'total': 0})

    except Exception as e:
        logger.exception("Error fetching playbook history")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/history', methods=['GET'])
@require_session
def get_all_playbook_history():
    """Get all playbook execution history"""
    try:
        limit = int(request.args.get('limit', 100))
        
        if DB_ENABLED:
            executions = execution_dao.get_recent(g.tenant_id, limit=limit)
            return jsonify({
                'history': executions,
                'total': len(executions)
            })
        else:
            return jsonify({'history': [], 'total': 0})

    except Exception as e:
        logger.exception("Error fetching playbook history")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/templates', methods=['GET'])
@require_session
def get_playbook_templates():
    """Get pre-built playbook templates"""
    templates = [
        {
            'id': 'ransomware_response',
            'name': 'Ransomware Rapid Response',
            'description': 'Immediately contain infected hosts and block IOCs',
            'trigger': 'ransomware',
            'actions': [
                {'type': 'contain_host', 'params': {}},
                {'type': 'create_ioc', 'params': {'ioc_type': 'sha256', 'severity': 'critical'}},
                {'type': 'close_detection', 'params': {}}
            ]
        },
        {
            'id': 'malware_containment',
            'name': 'Malware Containment & Analysis',
            'description': 'Contain host, kill malicious process, and collect file',
            'trigger': 'manual',
            'actions': [
                {'type': 'contain_host', 'params': {}},
                {'type': 'kill_process', 'params': {'process': 'malware.exe'}},
                {'type': 'tag_detection', 'params': {'tags': 'malware,contained,analyzing'}}
            ]
        },
        {
            'id': 'false_positive_cleanup',
            'name': 'Bulk False Positive Cleanup',
            'description': 'Close detection and add hash to exclusions',
            'trigger': 'manual',
            'actions': [
                {'type': 'close_detection', 'params': {}},
                {'type': 'create_ioc', 'params': {'ioc_type': 'sha256', 'severity': 'informational'}}
            ]
        },
        {
            'id': 'threat_hunt_response',
            'name': 'Threat Hunt Follow-up',
            'description': 'Tag, assign, and run forensics script',
            'trigger': 'manual',
            'actions': [
                {'type': 'tag_detection', 'params': {'tags': 'threat-hunt,requires-analysis'}},
                {'type': 'assign_to_user', 'params': {'user_uuid': 'YOUR_ANALYST_UUID'}},
                {'type': 'run_rtr_script', 'params': {'script_name': 'forensics_collector', 'arguments': '--full'}}
            ]
        }
    ]
    
    return jsonify({'templates': templates})

@app.route('/api/playbooks/from-template/<template_id>', methods=['POST'])
@require_session
def create_from_template(template_id):
    """Create playbook from template"""
    try:
        data = request.json or {}
        custom_name = data.get('name', '')
        
        # Get template
        templates_resp = get_playbook_templates()
        templates = templates_resp.get_json()['templates']
        template = next((t for t in templates if t['id'] == template_id), None)
        
        if not template:
            return jsonify({'error': 'Template not found'}), 404
        
        if DB_ENABLED:
            playbook = playbook_dao.create(g.tenant_id, {
                'name': custom_name or template['name'],
                'description': template['description'],
                'trigger': template['trigger'],
                'actions': template['actions'],
                'enabled': True
            })
            
            return jsonify({
                'status': 'success',
                'playbook': playbook
            })
        else:
            return jsonify({'error': 'Database not available'}), 500

    except Exception as e:
        logger.exception("Error creating playbook from template")
        return jsonify({'error': str(e)}), 500

@app.route('/api/playbooks/auto-trigger/status', methods=['GET'])
@require_session
def get_auto_trigger_status():
    """Get auto-trigger system status"""
    tenant_processed = len(processed_detections.get(g.tenant_id, set()))
    
    if DB_ENABLED:
        active_playbooks = playbook_dao.get_all(g.tenant_id)
        active_count = len([
            pb for pb in active_playbooks 
            if pb.get('enabled') and pb.get('trigger') != 'manual'
        ])
    else:
        active_count = 0
    
    return jsonify({
        'enabled': AUTO_TRIGGER_ENABLED,
        'interval_seconds': AUTO_TRIGGER_INTERVAL,
        'lookback_minutes': LOOKBACK_WINDOW,
        'processed_count': tenant_processed,
        'active_playbooks': active_count
    })

@app.route('/api/playbooks/auto-trigger/toggle', methods=['POST'])
@require_session
def toggle_auto_trigger():
    """Enable/disable auto-trigger system"""
    global AUTO_TRIGGER_ENABLED
    
    data = request.json or {}
    enabled = data.get('enabled', True)
    
    AUTO_TRIGGER_ENABLED = enabled
    
    return jsonify({
        'status': 'success',
        'enabled': AUTO_TRIGGER_ENABLED
    })

@app.route('/api/playbooks/auto-trigger/clear-cache', methods=['POST'])
@require_session
def clear_processed_cache():
    """Clear processed detections cache for tenant"""
    tenant_id = g.tenant_id
    count = len(processed_detections.get(tenant_id, set()))
    processed_detections[tenant_id] = set()
    
    return jsonify({
        'status': 'success',
        'message': f'Cleared {count} processed detection IDs',
        'cleared_count': count
    })

# ============================================================================
# VIRUSTOTAL
# ============================================================================

@app.route('/api/virustotal/hash/<hash_value>', methods=['GET'])
def virustotal_lookup(hash_value):
    """Look up hash in VirusTotal"""
    vt_api_key = request.headers.get('X-VT-API-Key')
    if not vt_api_key:
        return jsonify({'error': 'VirusTotal API key required'}), 401

    if not hash_value or len(hash_value) not in [32, 40, 64]:
        return jsonify({'error': 'Invalid hash format'}), 400

    url = f'https://www.virustotal.com/api/v3/files/{hash_value}'
    headers = {'x-apikey': vt_api_key}

    try:
        response = requests.get(url, headers=headers, timeout=10)

        if response.status_code == 200:
            data = response.json()
            attributes = data.get('data', {}).get('attributes', {})
            stats = attributes.get('last_analysis_stats', {})

            return jsonify({
                'malicious': stats.get('malicious', 0),
                'suspicious': stats.get('suspicious', 0),
                'undetected': stats.get('undetected', 0),
                'harmless': stats.get('harmless', 0),
                'total': sum(stats.values()),
                'names': attributes.get('names', [])[:20],
                'first_seen': attributes.get('first_submission_date'),
                'sha256': attributes.get('sha256', ''),
                'file_type': attributes.get('type_description', '')
            })

        elif response.status_code == 404:
            return jsonify({'error': 'Hash not found in VirusTotal database'}), 404
        else:
            return jsonify({'error': f'VirusTotal API error: {response.status_code}'}), 500

    except Exception as e:
        logger.exception("Error in VirusTotal lookup")
        return jsonify({'error': str(e)}), 500

# ============================================================================
# RTR COMMANDS - ALL TIERS
# ============================================================================

# Tier 0 - Basic
@app.route('/api/hosts/<device_id>/rtr/kill', methods=['POST'])
@require_session
def rtr_kill_process(device_id):
    """Kill a process"""
    data = request.json or {}
    process = data.get('process')
    if not process:
        return jsonify({'error': 'process is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="kill",
            batch_id=batch_id,
            command_string=f'process={process}',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR kill failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'kill', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/delete-file', methods=['POST'])
@require_session
def rtr_delete_file(device_id):
    """Delete a file"""
    data = request.json or {}
    path = data.get('path')
    if not path:
        return jsonify({'error': 'path is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="rm",
            batch_id=batch_id,
            command_string=f'path="{path}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR delete failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'delete_file', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Tier 1 - Read-only
@app.route('/api/hosts/<device_id>/rtr/filehash', methods=['POST'])
@require_session
def rtr_filehash(device_id):
    """Get file hash"""
    data = request.json or {}
    path = data.get('path')
    if not path:
        return jsonify({'error': 'path is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="filehash",
            batch_id=batch_id,
            command_string=f'path="{path}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR filehash failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'filehash', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/ls', methods=['POST'])
@require_session
def rtr_list_directory(device_id):
    """List directory"""
    data = request.json or {}
    path = data.get('path', 'C:\\')

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="ls",
            batch_id=batch_id,
            command_string=f'path="{path}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR ls failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'ls', 'path': path, 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/netstat', methods=['POST'])
@require_session
def rtr_netstat(device_id):
    """Get network connections"""
    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="netstat",
            batch_id=batch_id,
            command_string="netstat",
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR netstat failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'netstat', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/ps', methods=['POST'])
@require_session
def rtr_process_list(device_id):
    """List processes"""
    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="ps",
            batch_id=batch_id,
            command_string="ps",
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR ps failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'ps', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Tier 2 - Active Responder
@app.route('/api/hosts/<device_id>/rtr/reg-query', methods=['POST'])
@require_session
def rtr_registry_query(device_id):
    """Query registry"""
    data = request.json or {}
    key = data.get('key')
    if not key:
        return jsonify({'error': 'key is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="reg",
            batch_id=batch_id,
            command_string=f'query subkey="{key}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR reg query failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'reg_query', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/get-file', methods=['POST'])
@require_session
def rtr_get_file(device_id):
    """Retrieve file"""
    data = request.json or {}
    path = data.get('path')
    if not path:
        return jsonify({'error': 'path is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="get",
            batch_id=batch_id,
            command_string=f'path="{path}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR get file failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'get_file', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/memdump', methods=['POST'])
@require_session
def rtr_memory_dump(device_id):
    """Memory dump"""
    data = request.json or {}
    pid = data.get('pid', '')

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_string = f'pid={pid}' if pid else ''
        cmd_resp = rtr.batch_active_responder_command(
            base_command="memdump",
            batch_id=batch_id,
            command_string=cmd_string,
            host_ids=[device_id],
            timeout=300
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR memdump failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'memdump', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/cp', methods=['POST'])
@require_session
def rtr_copy_file(device_id):
    """Copy file"""
    data = request.json or {}
    source = data.get('source')
    destination = data.get('destination')
    if not source or not destination:
        return jsonify({'error': 'source and destination required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="cp",
            batch_id=batch_id,
            command_string=f'path="{source}" destination="{destination}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR cp failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'cp', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/zip', methods=['POST'])
@require_session
def rtr_zip_files(device_id):
    """Create ZIP archive"""
    data = request.json or {}
    path = data.get('path')
    destination = data.get('destination')
    if not path or not destination:
        return jsonify({'error': 'path and destination required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_active_responder_command(
            base_command="zip",
            batch_id=batch_id,
            command_string=f'path="{path}" destination="{destination}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR zip failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'zip', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# Tier 3 - Admin
@app.route('/api/rtr/scripts', methods=['GET'])
@require_session
def rtr_list_scripts():
    """List RTR scripts"""
    try:
        rtr = _get_rtr()
        response = rtr.list_scripts()
        if response.get("status_code") != 200:
            return jsonify({'error': 'Failed to list scripts'}), 500

        scripts = []
        for script in response.get("body", {}).get("resources", []):
            scripts.append({
                'id': script.get('id'),
                'name': script.get('name'),
                'description': script.get('description'),
                'platform': script.get('platform')
            })
        
        return jsonify({'scripts': scripts})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/runscript', methods=['POST'])
@require_session
def rtr_run_script(device_id):
    """Run script"""
    data = request.json or {}
    script = data.get('script')
    args = data.get('args', '')
    if not script:
        return jsonify({'error': 'script is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_string = f'CloudFile="{script}"'
        if args:
            cmd_string += f' CommandLine="{args}"'

        cmd_resp = rtr.batch_admin_cmd(
            base_command="runscript",
            batch_id=batch_id,
            command_string=cmd_string,
            host_ids=[device_id],
            timeout=120
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR runscript failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'runscript', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/put-file', methods=['POST'])
@require_session
def rtr_put_file(device_id):
    """Upload file"""
    data = request.json or {}
    path = data.get('path')
    description = data.get('description', '')
    if not path:
        return jsonify({'error': 'path is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_string = f'path="{path}"'
        if description:
            cmd_string += f' description="{description}"'

        cmd_resp = rtr.batch_admin_cmd(
            base_command="put",
            batch_id=batch_id,
            command_string=cmd_string,
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR put failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'put_file', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/reg-delete', methods=['POST'])
@require_session
def rtr_registry_delete(device_id):
    """Delete registry key"""
    data = request.json or {}
    key = data.get('key')
    if not key:
        return jsonify({'error': 'key is required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_admin_cmd(
            base_command="reg",
            batch_id=batch_id,
            command_string=f'delete subkey="{key}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR reg delete failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'reg_delete', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/reg-set', methods=['POST'])
@require_session
def rtr_registry_set(device_id):
    """Set registry value"""
    data = request.json or {}
    key = data.get('key')
    value = data.get('value')
    value_type = data.get('type', 'REG_SZ')
    if not key or value is None:
        return jsonify({'error': 'key and value required'}), 400

    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_admin_cmd(
            base_command="reg",
            batch_id=batch_id,
            command_string=f'set subkey="{key}" value="{value}" valuetype="{value_type}"',
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR reg set failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'reg_set', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/restart', methods=['POST'])
@require_session
def rtr_restart_host(device_id):
    """Restart host"""
    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_admin_cmd(
            base_command="restart",
            batch_id=batch_id,
            command_string="",
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR restart failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'restart', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/hosts/<device_id>/rtr/shutdown', methods=['POST'])
@require_session
def rtr_shutdown_host(device_id):
    """Shutdown host"""
    try:
        rtr = _get_rtr()
        init_resp = rtr.batch_init_sessions(body={"host_ids": [device_id], "queue_offline": False})
        if init_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'Failed to init RTR session'}), 500

        batch_id = init_resp.get("body", {}).get("batch_id")
        cmd_resp = rtr.batch_admin_cmd(
            base_command="shutdown",
            batch_id=batch_id,
            command_string="",
            host_ids=[device_id]
        )

        if cmd_resp.get("status_code") not in (200, 201):
            return jsonify({'error': 'RTR shutdown failed'}), 500

        output = _extract_rtr_output(cmd_resp, device_id)
        return jsonify({'status': 'success', 'action': 'shutdown', 'batch_id': batch_id, **output})
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# ============================================================================
# REPORTS
# ============================================================================

def send_report_email(to_addresses, subject, body, filename, report_data, mimetype):
    """Send a report via the configured SMTP relay."""
    if not EMAIL_ENABLED:
        raise RuntimeError("Email sending is disabled")

    # Normalise list of addresses
    if isinstance(to_addresses, str):
        to_addresses = [addr.strip() for addr in to_addresses.split(',') if addr.strip()]

    if not to_addresses:
        raise ValueError("No recipient email addresses supplied")

    msg = EmailMessage()
    msg['Subject'] = subject or 'Falcon Manager Pro Report'
    msg['From'] = SMTP_FROM
    msg['To'] = ', '.join(to_addresses)

    msg.set_content(body or 'Please find the Falcon Manager Pro report attached.')

    try:
        maintype, subtype = mimetype.split('/', 1)
    except ValueError:
        maintype, subtype = 'application', 'octet-stream'

    msg.add_attachment(
        report_data,
        maintype=maintype,
        subtype=subtype,
        filename=filename
    )

    # GCP SMTP relay on port 587 with STARTTLS; auth is off, IP-restricted
    with smtplib.SMTP(SMTP_HOST, SMTP_PORT) as server:
        if SMTP_USE_TLS:
            server.starttls()
        server.send_message(msg)

@app.route('/api/reports/generate', methods=['POST'])
@require_session
@app.route('/api/reports/generate', methods=['POST'])
@require_session
def generate_report():
    """Generate comprehensive reports"""
    try:
        data = request.json or {}
        report_type = data.get('type', 'executive')
        report_format = data.get('format', 'pdf')
        title = data.get('title', 'Security Operations Report')
        recipients = data.get('recipients', '').strip()
        mode = data.get('mode', 'download')       # 'download' or 'email'
        email_body = data.get('emailBody', '')

        # Time range
        time_range_str = data.get('timeRange', '24h')
        time_range = 24
        if time_range_str != 'custom':
            time_range = int(time_range_str.rstrip('hd'))
            if time_range_str.endswith('d'):
                time_range = time_range * 24

        severity_filter = data.get('severityFilter', 'all')
        status_filter = data.get('statusFilter', 'all')
        include_summary = data.get('includeSummary', True)
        include_charts = data.get('includeCharts', True)
        include_detections = data.get('includeDetections', True)
        include_hosts = data.get('includeHosts', False)
        # Accept both includeIOCs (old) and includeIocs (new)
        include_iocs = data.get('includeIOCs', data.get('includeIocs', False))

        # Falcon clients
        falcon_detect = Alerts(auth_object=g.falcon_auth)
        falcon_hosts = Hosts(auth_object=g.falcon_auth)
        falcon_ioc = IOC(auth_object=g.falcon_auth)

        # --------- severity helper (mirrors /api/detections logic, simplified) ---------
        def _get_severity(det):
            """Extract severity from detection, checking multiple possible fields."""
            # Try max_severity_displayname first (most common)
            if det.get('max_severity_displayname'):
                return det['max_severity_displayname'].lower()

            # Try severity_name
            if det.get('severity_name'):
                return det['severity_name'].lower()

            # Try numeric max_severity
            severity_num = det.get('max_severity')
            if severity_num is not None:
                severity_map = {
                    10: 'informational',
                    20: 'low',
                    30: 'medium',
                    40: 'high',
                    50: 'critical',
                    70: 'critical'
                }
                mapped = severity_map.get(severity_num, 'unknown')
                if mapped != 'unknown':
                    return mapped

            # Try severity field (string or int)
            severity_val = det.get('severity')
            if severity_val:
                if isinstance(severity_val, str):
                    return severity_val.lower()
                elif isinstance(severity_val, int):
                    severity_map = {
                        10: 'informational',
                        20: 'low',
                        30: 'medium',
                        40: 'high',
                        50: 'critical',
                        70: 'critical'
                    }
                    mapped = severity_map.get(severity_val, 'unknown')
                    if mapped != 'unknown':
                        return mapped

            # Try behavior severity as last resort
            behaviors = det.get('behaviors', [])
            if behaviors:
                first_behavior = behaviors[0]

                if first_behavior.get('severity_name'):
                    return first_behavior['severity_name'].lower()

                behavior_severity = first_behavior.get('severity')
                if behavior_severity is not None:
                    if isinstance(behavior_severity, str):
                        return behavior_severity.lower()
                    elif isinstance(behavior_severity, int):
                        severity_map = {
                            10: 'informational',
                            20: 'low',
                            30: 'medium',
                            40: 'high',
                            50: 'critical',
                            70: 'critical'
                        }
                        mapped = severity_map.get(behavior_severity, 'unknown')
                        if mapped != 'unknown':
                            return mapped

            return 'unknown'

        # --------- time filters ---------
        end_time = datetime.utcnow()
        start_time = end_time - timedelta(hours=time_range)

        time_filter = f"created_timestamp:>'{start_time.isoformat()}Z'"
        filters = [time_filter]

        if severity_filter != 'all':
            filters.append(f"max_severity_displayname:'{severity_filter}'")
        if status_filter != 'all':
            filters.append(f"status:'{status_filter}'")

        filter_string = "+".join(filters)

        # --------- detections (true totals + limited details) ---------
        detections_data = []
        total_detections = 0

        if include_detections or report_type in ['executive', 'detailed', 'timeline']:
            response = falcon_detect.query_alerts(filter=filter_string, limit=MAX_DETECT_LIMIT)
            if response.get('status_code') == 200:
                detection_ids = response['body'].get('resources', []) or []
                total_detections = len(detection_ids)

                if detection_ids:
                    # Only fetch details for first N to keep report sane
                    detail_ids = detection_ids[:500]
                    details = falcon_detect.get_alerts(ids=detail_ids)
                    if details.get('status_code') == 200:
                        for det in details['body'].get('resources', []):
                            behaviors = det.get('behaviors', []) or [{}]
                            first_behavior = behaviors[0] if behaviors else {}
                            device = det.get('device', {}) or {}

                            sev = _get_severity(det)
                            detections_data.append({
                                'id': det.get('detection_id') or det.get('id'),
                                'severity': sev,
                                'status': det.get('status', 'new'),
                                'host': device.get('hostname', 'Unknown'),
                                'tactic': first_behavior.get('tactic', 'Unknown'),
                                'timestamp': det.get('created_timestamp', ''),
                                'description': first_behavior.get('description', '')
                            })

        # --------- hosts (true-ish totals + limited details) ---------
        hosts_data = []
        total_hosts = 0

        if include_hosts or report_type == 'host_inventory':
            host_ids = []
            host_response = falcon_hosts.query_devices_by_filter_scroll(
                filter=f"first_seen:>='{start_time.isoformat()}Z'"
            )
            if host_response.get('status_code') == 200:
                host_ids = host_response['body'].get('resources', []) or []
                total_hosts = len(host_ids)

                if host_ids:
                    host_details = falcon_hosts.get_device_details(ids=host_ids[:500])
                    if host_details.get('status_code') == 200:
                        for host in host_details['body'].get('resources', []):
                            hosts_data.append({
                                'hostname': host.get('hostname', 'Unknown'),
                                'os_version': host.get('os_version', 'Unknown'),
                                'last_seen': host.get('last_seen', ''),
                                'status': host.get('status', 'Unknown'),
                                'agent_version': host.get('agent_version', '')
                            })

        # --------- IOCs (DB IOCs + CrowdStrike IOCs with de-dup) ---------
        iocs_data = []
        total_iocs = 0

        if include_iocs or report_type == 'ioc_intelligence':
            # 1) DB IOCs
            if DB_ENABLED:
                try:
                    db_iocs = ioc_dao.get_all(g.tenant_id)
                    for ioc in db_iocs:
                        iocs_data.append({
                            'type': ioc['ioc_type'],
                            'value': ioc['ioc_value'],
                            'severity': ioc['severity'],
                            'policy': ioc['policy'],
                            'description': ioc.get('description', '')
                        })
                except Exception as e:
                    app.logger.error(f"Error fetching DB IOCs for report: {e}")

            # 2) CrowdStrike IOCs (optional, best-effort)
            try:
                ioc_filter = f"last_updated:>='{start_time.isoformat()}Z'"
                ioc_response = falcon_ioc.indicator_search(
                    filter=ioc_filter,
                    limit=MAX_IOC_LIMIT
                )
                if ioc_response.get('status_code') == 200:
                    ioc_ids = ioc_response['body'].get('resources', []) or []
                    if ioc_ids:
                        ioc_details = falcon_ioc.indicator_get(ids=ioc_ids[:500])
                        if ioc_details.get('status_code') == 200:
                            for ioc in ioc_details['body'].get('resources', []):
                                iocs_data.append({
                                    'type': ioc.get('type'),
                                    'value': ioc.get('value'),
                                    'severity': (ioc.get('severity') or 'medium').lower(),
                                    'policy': ioc.get('action', 'detect'),
                                    'description': ioc.get('description', '')
                                })
            except Exception as e:
                app.logger.error(f"Error fetching CrowdStrike IOCs for report: {e}")

            # --- IOC DE-DUPLICATION HERE ---
            seen = set()
            deduped_iocs = []
            for ioc in iocs_data:
                ioc_type = (ioc.get('type') or '').strip().lower()
                ioc_value = (ioc.get('value') or '').strip().lower()
                key = (ioc_type, ioc_value)
                if key in seen:
                    continue
                seen.add(key)
                deduped_iocs.append(ioc)
            iocs_data = deduped_iocs

            total_iocs = len(iocs_data)

        # --------- stats (severity + status) ---------
        severity_counts = {}
        status_counts = {}
        for det in detections_data:
            sev = (det.get('severity') or 'unknown').lower()
            severity_counts[sev] = severity_counts.get(sev, 0) + 1

            stat = (det.get('status') or 'new').lower()
            status_counts[stat] = status_counts.get(stat, 0) + 1

        # --------- filename ---------
        timestamp_str = datetime.utcnow().strftime("%Y%m%d_%H%M%S")
        filename = f'falcon_{report_type}_report_{timestamp_str}.{report_format}'

        # --------- build report data ---------
        if report_format == 'pdf':
            buffer = _generate_pdf_report(
                report_type,
                title,
                time_range,
                detections_data,
                hosts_data,
                iocs_data,
                severity_counts,
                status_counts,
                include_summary,
                include_charts,
                total_detections=total_detections,
                total_hosts=total_hosts,
                total_iocs=total_iocs,
            )
            buffer.seek(0)
            report_data = buffer.getvalue()
            mimetype = 'application/pdf'

        elif report_format == 'csv':
            buffer = BytesIO()
            writer = csv.writer(buffer)

            # Totals section at the top
            writer.writerow(['Total Detections', total_detections])
            writer.writerow(['Total Hosts', total_hosts])
            writer.writerow(['Total IOCs', total_iocs])
            writer.writerow([])  # blank line separator

            # Detail section
            writer.writerow(['ID', 'Severity', 'Status', 'Host', 'Tactic', 'Timestamp', 'Description'])
            for det in detections_data:
                writer.writerow([
                    det.get('id', ''),
                    det.get('severity', ''),
                    det.get('status', ''),
                    det.get('host', ''),
                    det.get('tactic', ''),
                    det.get('timestamp', ''),
                    det.get('description', '')
                ])

            buffer.seek(0)
            report_data = buffer.getvalue()
            mimetype = 'text/csv'


        elif report_format == 'json':
            report_json = {
                'title': title,
                'generated_at': datetime.utcnow().isoformat(),
                'tenant_id': g.tenant_id,
                'time_range_hours': time_range,
                'statistics': {
                    'total_detections': total_detections,
                    'total_hosts': total_hosts,
                    'total_iocs': total_iocs,
                    'severity_breakdown': severity_counts,
                    'status_breakdown': status_counts
                },
                'detections': detections_data if include_detections else [],
                'hosts': hosts_data if include_hosts else [],
                'iocs': iocs_data if include_iocs else []
            }
            report_data = json.dumps(report_json, indent=2).encode('utf-8')
            mimetype = 'application/json'

        else:
            return jsonify({'error': f'Unsupported format: {report_format}'}), 400

        # --------- email vs download ---------
        if mode == 'email':
            if not recipients:
                return jsonify({'error': 'Recipient email address is required for email delivery'}), 400

            try:
                send_report_email(
                    to_addresses=recipients,
                    subject=title,
                    body=email_body,
                    filename=filename,
                    report_data=report_data,
                    mimetype=mimetype
                )
            except Exception as e:
                app.logger.error(f"Failed to send report email: {e}")
                return jsonify({'error': f'Email send failed: {e}'}), 500

            return jsonify({
                'status': 'success',
                'message': f'Report emailed to: {recipients}'
            })

        return send_file(
            io.BytesIO(report_data),
            mimetype=mimetype,
            as_attachment=True,
            download_name=filename
        )

    except Exception as e:
        app.logger.error(f"Report generation failed: {e}")
        return jsonify({'error': str(e)}), 500


# ============================================================================
# CACHE & HEALTH
# ============================================================================

@app.route('/api/cache/clear', methods=['POST'])
@require_session
def clear_cache():
    """Clear tenant cache"""
    if g.tenant_id in tenant_caches:
        del tenant_caches[g.tenant_id]
    
    return jsonify({'status': 'success', 'message': 'Cache cleared'})

@app.route('/api/cache/info', methods=['GET'])
@require_session
def cache_info():
    """Get cache info"""
    if g.tenant_id in tenant_caches:
        cache = tenant_caches[g.tenant_id]
        age = int(time.time() - cache['last_fetch'])
        return jsonify({
            'cached': True,
            'host_count': len(cache['hosts']),
            'cache_age_seconds': age,
            'cache_remaining_seconds': max(0, CACHE_TIMEOUT - age)
        })
    
    return jsonify({'cached': False, 'host_count': 0})

@app.route('/api/health', methods=['GET'])
def health_check():
    """Health check"""
    return jsonify({
        'status': 'healthy',
        'database': DB_ENABLED,
        'active_sessions': len(active_sessions),
        'timestamp': datetime.utcnow().isoformat()
    }), 200

@app.route('/api/info', methods=['GET'])
def api_info():
    """API info"""
    return jsonify({
        'status': 'Falcon Manager Pro - Multi-Tenant Edition',
        'version': '4.0',
        'database_enabled': DB_ENABLED,
        'email_enabled': EMAIL_ENABLED,
        'features': [
            'Multi-Tenant Database Architecture',
            'Automatic Tenant Creation',
            'Session-Based Authentication',
            'Per-Tenant Data Isolation',
            'Per-Tenant Caching',
            'CrowdStrike Falcon Integration',
            'VirusTotal Integration',
            'Automated Playbooks',
            'Auto-Trigger System',
            'Real-Time Response Commands (All Tiers)',
            'Report Generation with Email',
            'Hash Analysis Tools'
        ]
    })

@app.route('/api/debug/hosts-test', methods=['GET'])
@require_session
def debug_hosts_test():
    """Debug endpoint"""
    try:
        falcon_hosts = Hosts(auth_object=g.falcon_auth)
        response = falcon_hosts.query_devices_by_filter_scroll(limit=5, sort='last_seen.desc')
        
        return jsonify({
            'test': 'success',
            'status_code': response.get('status_code'),
            'found_hosts': len(response.get('body', {}).get('resources', [])),
            'tenant_id': g.tenant_id
        })
    except Exception as e:
        return jsonify({'test': 'failed', 'error': str(e)}), 500

@app.route('/api/debug/iocs-test', methods=['GET'])
@require_session
def debug_iocs_test():
    """Debug IOC endpoint - shows detailed IOC fetch information"""
    try:
        result = {
            'tenant_id': g.tenant_id,
            'db_enabled': DB_ENABLED,
            'database_iocs': [],
            'crowdstrike_iocs': [],
            'errors': []
        }
        
        # Check database IOCs
        if DB_ENABLED:
            try:
                db_iocs = ioc_dao.get_all(g.tenant_id)
                result['database_iocs'] = {
                    'count': len(db_iocs),
                    'samples': db_iocs[:3] if db_iocs else []
                }
            except Exception as e:
                result['errors'].append(f"Database error: {str(e)}")
        
        # Check CrowdStrike IOCs
        try:
            falcon_ioc = IOC(auth_object=g.falcon_auth)
            search_response = falcon_ioc.indicator_search(limit=MAX_IOC_LIMIT)
            
            result['crowdstrike_search'] = {
                'status_code': search_response.get('status_code'),
                'ioc_count': len(search_response.get('body', {}).get('resources', []))
            }
            
            if search_response.get('status_code') == 200:
                ioc_ids = search_response['body'].get('resources', [])[:5]  # Sample first 5
                if ioc_ids:
                    details_response = falcon_ioc.indicator_get(ids=ioc_ids)
                    result['crowdstrike_iocs'] = {
                        'status_code': details_response.get('status_code'),
                        'sample_iocs': details_response.get('body', {}).get('resources', [])
                    }
            else:
                result['errors'].append(f"CrowdStrike search failed: {search_response.get('body')}")
                
        except Exception as e:
            result['errors'].append(f"CrowdStrike error: {str(e)}")
        
        return jsonify(result)
        
    except Exception as e:
        return jsonify({'test': 'failed', 'error': str(e)}), 500

@app.route('/')
def index():
    """Root endpoint"""
    return jsonify({
        'status': 'Falcon Manager Pro API',
        'version': '4.0',
        'database': DB_ENABLED,
        'documentation': '/api/info'
    })

# Shut down scheduler
atexit.register(lambda: scheduler.shutdown())

if __name__ == '__main__':
    app.run(debug=True, port=5003, host='0.0.0.0')