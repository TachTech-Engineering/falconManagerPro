import os
import psycopg2
from psycopg2.extras import RealDictCursor, execute_values
from contextlib import contextmanager
from datetime import datetime
import json
from typing import List, Dict, Optional, Any
import logging

logger = logging.getLogger(__name__)


class Database:
    """PostgreSQL database connection manager"""
    
    def __init__(self):
        self.host = os.getenv('DB_HOST', 'localhost')
        self.port = int(os.getenv('DB_PORT', 5432))
        self.database = os.getenv('DB_NAME', 'falconmanager')
        self.user = os.getenv('DB_USER', 'falcon_app')
        self.password = os.getenv('DB_PASSWORD')
        
    def get_connection(self):
        """Create a new database connection"""
        return psycopg2.connect(
            host=self.host,
            port=self.port,
            database=self.database,
            user=self.user,
            password=self.password,
            cursor_factory=RealDictCursor
        )
    
    @contextmanager
    def get_cursor(self, commit=True):
        """Context manager for database operations"""
        conn = self.get_connection()
        cursor = conn.cursor()
        try:
            yield cursor
            if commit:
                conn.commit()
        except Exception as e:
            conn.rollback()
            logger.error(f"Database error: {e}")
            raise
        finally:
            cursor.close()
            conn.close()


class TenantDAO:
    """Data Access Object for Tenants"""
    
    def __init__(self, db: Database):
        self.db = db
    
    def get_by_api_key(self, api_key: str) -> Optional[Dict[str, Any]]:
        """Get tenant by API key"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM tenants 
                WHERE api_key = %s 
                  AND is_active = true 
                  AND deleted_at IS NULL
            """, (api_key,))
            return cursor.fetchone()
    
    def get_by_id(self, tenant_id: str) -> Optional[Dict[str, Any]]:
        """Get tenant by ID"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM tenants 
                WHERE id = %s 
                  AND is_active = true 
                  AND deleted_at IS NULL
            """, (tenant_id,))
            return cursor.fetchone()
    
    def get_by_domain(self, domain: str) -> Optional[Dict[str, Any]]:
        """Get tenant by domain"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM tenants 
                WHERE domain = %s 
                  AND is_active = true 
                  AND deleted_at IS NULL
            """, (domain,))
            return cursor.fetchone()
    
    def create(self, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new tenant"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO tenants (
                    name, domain, api_key, crowdstrike_client_id,
                    crowdstrike_client_secret, crowdstrike_base_url,
                    virustotal_api_key, plan, max_users, max_playbooks
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (
                data['name'],
                data['domain'],
                data['api_key'],
                data.get('crowdstrike_client_id'),
                data.get('crowdstrike_client_secret'),
                data.get('crowdstrike_base_url', 'https://api.crowdstrike.com'),
                data.get('virustotal_api_key'),
                data.get('plan', 'free'),
                data.get('max_users', 5),
                data.get('max_playbooks', 10)
            ))
            return cursor.fetchone()
    
    def update(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update tenant"""
        fields = []
        values = []
        
        for key, value in data.items():
            if key not in ['id', 'created_at', 'updated_at', 'deleted_at']:
                fields.append(f"{key} = %s")
                values.append(value)
        
        values.append(tenant_id)
        
        with self.db.get_cursor() as cursor:
            cursor.execute(f"""
                UPDATE tenants 
                SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP
                WHERE id = %s
                RETURNING *
            """, values)
            return cursor.fetchone()


class PlaybookDAO:
    """Data Access Object for Playbooks"""
    
    def __init__(self, db: Database):
        self.db = db
    
    def get_all(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all playbooks for a tenant"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM playbooks
                WHERE tenant_id = %s AND deleted_at IS NULL
                ORDER BY created_at DESC
            """, (tenant_id,))
            return cursor.fetchall()
    
    def get_by_id(self, tenant_id: str, playbook_id: str) -> Optional[Dict[str, Any]]:
        """Get playbook by ID"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM playbooks
                WHERE tenant_id = %s AND id = %s AND deleted_at IS NULL
            """, (tenant_id, playbook_id))
            return cursor.fetchone()
    
    def get_by_trigger(self, tenant_id: str, trigger: str) -> List[Dict[str, Any]]:
        """Get enabled playbooks by trigger type"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM playbooks
                WHERE tenant_id = %s 
                  AND trigger = %s 
                  AND enabled = true 
                  AND deleted_at IS NULL
                ORDER BY created_at
            """, (tenant_id, trigger))
            return cursor.fetchall()
    
    def create(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new playbook"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO playbooks (
                    tenant_id, created_by, name, description, 
                    trigger, actions, enabled
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (
                tenant_id,
                data.get('created_by'),
                data['name'],
                data.get('description'),
                data['trigger'],
                json.dumps(data.get('actions', [])),
                data.get('enabled', True)
            ))
            return cursor.fetchone()
    
    def update(self, tenant_id: str, playbook_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update playbook"""
        fields = []
        values = []
        
        for key, value in data.items():
            if key not in ['id', 'tenant_id', 'created_at', 'updated_at', 'deleted_at']:
                if key == 'actions':
                    fields.append(f"{key} = %s")
                    values.append(json.dumps(value))
                else:
                    fields.append(f"{key} = %s")
                    values.append(value)
        
        values.extend([tenant_id, playbook_id])
        
        with self.db.get_cursor() as cursor:
            cursor.execute(f"""
                UPDATE playbooks 
                SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP
                WHERE tenant_id = %s AND id = %s
                RETURNING *
            """, values)
            return cursor.fetchone()
    
    def delete(self, tenant_id: str, playbook_id: str) -> bool:
        """Soft delete playbook"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE playbooks 
                SET deleted_at = CURRENT_TIMESTAMP
                WHERE tenant_id = %s AND id = %s
            """, (tenant_id, playbook_id))
            return cursor.rowcount > 0
    
    def record_execution(self, tenant_id: str, playbook_id: str) -> None:
        """Record playbook execution"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE playbooks 
                SET execution_count = execution_count + 1,
                    last_executed_at = CURRENT_TIMESTAMP
                WHERE tenant_id = %s AND id = %s
            """, (tenant_id, playbook_id))


class ExecutionDAO:
    """Data Access Object for Playbook Executions"""
    
    def __init__(self, db: Database):
        self.db = db
    
    def create(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create execution record"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO playbook_executions (
                    tenant_id, playbook_id, executed_by, trigger_type,
                    target_type, target_id, results, total_actions,
                    successful_actions, failed_actions, skipped_actions,
                    status, error_message
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (
                tenant_id,
                data['playbook_id'],
                data.get('executed_by'),
                data['trigger_type'],
                data['target_type'],
                data['target_id'],
                json.dumps(data.get('results', [])),
                data['total_actions'],
                data['successful_actions'],
                data['failed_actions'],
                data['skipped_actions'],
                data['status'],
                data.get('error_message')
            ))
            return cursor.fetchone()
    
    def complete(self, execution_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Complete execution record"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE playbook_executions 
                SET completed_at = CURRENT_TIMESTAMP,
                    duration_ms = %s,
                    status = %s,
                    results = %s,
                    successful_actions = %s,
                    failed_actions = %s,
                    skipped_actions = %s,
                    error_message = %s
                WHERE id = %s
                RETURNING *
            """, (
                data.get('duration_ms'),
                data['status'],
                json.dumps(data.get('results', [])),
                data['successful_actions'],
                data['failed_actions'],
                data['skipped_actions'],
                data.get('error_message'),
                execution_id
            ))
            return cursor.fetchone()
    
    def get_recent(self, tenant_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get recent executions"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT e.*, p.name as playbook_name
                FROM playbook_executions e
                JOIN playbooks p ON e.playbook_id = p.id
                WHERE e.tenant_id = %s
                ORDER BY e.started_at DESC
                LIMIT %s
            """, (tenant_id, limit))
            return cursor.fetchall()


class IOCDAO:
    """Data Access Object for Custom IOCs"""
    
    def __init__(self, db: Database):
        self.db = db
    
    def get_all(self, tenant_id: str) -> List[Dict[str, Any]]:
        """Get all IOCs for a tenant"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM custom_iocs
                WHERE tenant_id = %s 
                  AND is_active = true 
                  AND deleted_at IS NULL
                ORDER BY created_at DESC
            """, (tenant_id,))
            return cursor.fetchall()
    
    def get_by_id(self, tenant_id: str, ioc_id: str) -> Optional[Dict[str, Any]]:
        """Get IOC by ID"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT * FROM custom_iocs
                WHERE tenant_id = %s AND id = %s AND deleted_at IS NULL
            """, (tenant_id, ioc_id))
            return cursor.fetchone()
    
    def create(self, tenant_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Create a new IOC"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO custom_iocs (
                    tenant_id, created_by, ioc_type, ioc_value,
                    policy, severity, description, tags
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s)
                RETURNING *
            """, (
                tenant_id,
                data.get('created_by'),
                data['ioc_type'],
                data['ioc_value'],
                data.get('policy', 'detect'),
                data.get('severity', 'medium'),
                data.get('description'),
                data.get('tags', [])
            ))
            return cursor.fetchone()
    
    def update(self, tenant_id: str, ioc_id: str, data: Dict[str, Any]) -> Dict[str, Any]:
        """Update IOC"""
        fields = []
        values = []
        
        for key, value in data.items():
            if key not in ['id', 'tenant_id', 'created_at', 'updated_at', 'deleted_at']:
                fields.append(f"{key} = %s")
                values.append(value)
        
        values.extend([tenant_id, ioc_id])
        
        with self.db.get_cursor() as cursor:
            cursor.execute(f"""
                UPDATE custom_iocs 
                SET {', '.join(fields)}, updated_at = CURRENT_TIMESTAMP
                WHERE tenant_id = %s AND id = %s
                RETURNING *
            """, values)
            return cursor.fetchone()
    
    def delete(self, tenant_id: str, ioc_id: str) -> bool:
        """Soft delete IOC"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE custom_iocs 
                SET deleted_at = CURRENT_TIMESTAMP, is_active = false
                WHERE tenant_id = %s AND id = %s
            """, (tenant_id, ioc_id))
            return cursor.rowcount > 0
    
    def mark_synced(self, tenant_id: str, ioc_id: str, crowdstrike_id: str) -> None:
        """Mark IOC as synced to CrowdStrike"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                UPDATE custom_iocs 
                SET crowdstrike_id = %s, 
                    synced_at = CURRENT_TIMESTAMP
                WHERE tenant_id = %s AND id = %s
            """, (crowdstrike_id, tenant_id, ioc_id))

class DetectionDAO:
    """Data Access Object for Detections"""
    
    def __init__(self, db: Database):
        self.db = db
    
    def create_or_update(self, tenant_id: str, detection_data: Dict[str, Any]) -> Optional[str]:
        """Store or update a single detection"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                INSERT INTO detections (
                    tenant_id, detection_id, severity, status, timestamp,
                    host_name, host_id, tactic, technique, description,
                    has_hash, raw_data, first_seen, last_updated
                )
                VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())
                ON CONFLICT (tenant_id, detection_id) 
                DO UPDATE SET
                    severity = EXCLUDED.severity,
                    status = EXCLUDED.status,
                    timestamp = EXCLUDED.timestamp,
                    host_name = EXCLUDED.host_name,
                    host_id = EXCLUDED.host_id,
                    tactic = EXCLUDED.tactic,
                    technique = EXCLUDED.technique,
                    description = EXCLUDED.description,
                    has_hash = EXCLUDED.has_hash,
                    raw_data = EXCLUDED.raw_data,
                    last_updated = NOW()
                RETURNING id
            """, (
                tenant_id,
                detection_data.get('id'),
                detection_data.get('severity'),
                detection_data.get('status'),
                detection_data.get('timestamp'),
                detection_data.get('host'),
                detection_data.get('host_id'),
                detection_data.get('tactic') or detection_data.get('behavior'),
                detection_data.get('technique'),
                detection_data.get('description'),
                detection_data.get('has_hash', False),
                json.dumps(detection_data)
            ))
            result = cursor.fetchone()
            return result['id'] if result else None
    
    def bulk_create_or_update(self, tenant_id: str, detections: List[Dict[str, Any]]) -> int:
        """Bulk insert/update detections for performance"""
        if not detections:
            return 0
        
        with self.db.get_cursor() as cursor:
            values = []
            for det in detections:
                values.append((
                    tenant_id,
                    det['id'],
                    det.get('severity'),
                    det.get('status'),
                    det.get('timestamp'),
                    det.get('host'),
                    det.get('host_id'),
                    det.get('tactic') or det.get('behavior'),
                    det.get('technique'),
                    det.get('description'),
                    det.get('has_hash', False),
                    json.dumps(det)
                ))
            
            execute_values(cursor, """
                INSERT INTO detections (
                    tenant_id, detection_id, severity, status, timestamp,
                    host_name, host_id, tactic, technique, description,
                    has_hash, raw_data, first_seen, last_updated
                ) VALUES %s
                ON CONFLICT (tenant_id, detection_id) 
                DO UPDATE SET
                    severity = EXCLUDED.severity,
                    status = EXCLUDED.status,
                    timestamp = EXCLUDED.timestamp,
                    host_name = EXCLUDED.host_name,
                    host_id = EXCLUDED.host_id,
                    tactic = EXCLUDED.tactic,
                    technique = EXCLUDED.technique,
                    description = EXCLUDED.description,
                    has_hash = EXCLUDED.has_hash,
                    raw_data = EXCLUDED.raw_data,
                    last_updated = NOW()
            """, values, template="(%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, NOW(), NOW())")
            
            return len(detections)

    def get_by_tenant(self, tenant_id: str, hours: int = 24, severity: str = None, status: str = None, limit: int = 5000) -> List[Dict[str, Any]]:
        """Get detections from database with filtering"""
        with self.db.get_cursor(commit=False) as cursor:
            # Build WHERE clauses
            where_clauses = ["tenant_id = %s"]
            params = [tenant_id]
            
            # Time filter
            if hours:
                where_clauses.append("timestamp >= NOW() - INTERVAL '%s hours'")
                params.append(hours)
            
            # Severity filter
            if severity and severity != 'all':
                where_clauses.append("LOWER(severity) = LOWER(%s)")
                params.append(severity)
            
            # Status filter
            if status and status != 'all':
                where_clauses.append("LOWER(status) = LOWER(%s)")
                params.append(status)
            
            where_clause = " AND ".join(where_clauses)
            
            query = f"""
                SELECT 
                    detection_id,
                    severity,
                    status,
                    timestamp,
                    host_name,
                    host_id,
                    tactic,
                    technique,
                    description,
                    has_hash,
                    raw_data,
                    first_seen
                FROM detections
                WHERE {where_clause}
                ORDER BY timestamp DESC
                LIMIT %s
            """
            params.append(limit)
            
            cursor.execute(query, params)
            return cursor.fetchall()
    
    def get_by_timerange(self, tenant_id: str, hours: int = 24, 
                         severity: Optional[str] = None,
                         status: Optional[str] = None,
                         limit: int = 5000) -> List[Dict[str, Any]]:
        """Get detections from database for specified timerange"""
        with self.db.get_cursor(commit=False) as cursor:
            query = """
                SELECT 
                    detection_id as id,
                    severity,
                    status,
                    timestamp,
                    host_name as host,
                    host_id,
                    tactic as behavior,
                    technique,
                    description,
                    has_hash,
                    raw_data,
                    first_seen,
                    last_updated
                FROM detections
                WHERE tenant_id = %s
                  AND timestamp > NOW() - INTERVAL '%s hours'
            """
            params = [tenant_id, hours]
            
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            
            if status:
                query += " AND status = %s"
                params.append(status)
            
            query += " ORDER BY timestamp DESC LIMIT %s"
            params.append(limit)
            
            cursor.execute(query, params)
            results = cursor.fetchall()
            
            # Parse raw_data for additional fields
            for det in results:
                if det.get('raw_data'):
                    try:
                        raw = det['raw_data']
                        if isinstance(raw, str):
                            raw = json.loads(raw)
                        # Merge useful fields from raw data
                        det.update({
                            'name': raw.get('name', det.get('behavior')),
                            'assigned_to': raw.get('assigned_to', 'Unassigned'),
                            'scenario': raw.get('scenario', '')
                        })
                    except:
                        pass
            
            return results
    
    def get_statistics(self, tenant_id: str, days: int = 30) -> List[Dict[str, Any]]:
        """Get detection statistics over time"""
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT 
                    DATE(timestamp) as date,
                    severity,
                    COUNT(*) as count
                FROM detections
                WHERE tenant_id = %s
                  AND timestamp > NOW() - INTERVAL '%s days'
                GROUP BY DATE(timestamp), severity
                ORDER BY date DESC
            """, (tenant_id, days))
            return cursor.fetchall()

    def get_hourly_stats(self, tenant_id: str, hours: int = 24):
        with self.db.get_cursor(commit=False) as cursor:
            cursor.execute("""
                SELECT 
                    DATE_TRUNC('hour', timestamp) AS hour,
                    severity,
                    COUNT(*) AS count
                FROM detections
                WHERE tenant_id = %s
                    AND timestamp >= NOW() - INTERVAL '%s hours'
                GROUP BY hour, severity
                ORDER BY hour ASC
            """, (tenant_id, hours))

            return cursor.fetchall()

    
    def get_count(self, tenant_id: str, hours: int = 24, 
                  severity: Optional[str] = None) -> int:
        """Get total detection count for timerange"""
        with self.db.get_cursor(commit=False) as cursor:
            query = """
                SELECT COUNT(*) as count
                FROM detections
                WHERE tenant_id = %s
                  AND timestamp > NOW() - INTERVAL '%s hours'
            """
            params = [tenant_id, hours]
            
            if severity:
                query += " AND severity = %s"
                params.append(severity)
            
            cursor.execute(query, params)
            result = cursor.fetchone()
            return result['count'] if result else 0
    
    def delete_old_records(self, tenant_id: str, days: int = 90) -> int:
        """Delete detections older than specified days (data retention)"""
        with self.db.get_cursor() as cursor:
            cursor.execute("""
                DELETE FROM detections
                WHERE tenant_id = %s
                  AND timestamp < NOW() - INTERVAL '%s days'
            """, (tenant_id, days))
            return cursor.rowcount


def init_database():
    """
    Initialize database connection and test connectivity.
    Returns True if database is available, False otherwise.
    """
    try:
        with db.get_cursor(commit=False) as cursor:
            cursor.execute("SELECT 1")
            result = cursor.fetchone()
            if result:
                logger.info("✅ Database connection successful")
                return True
    except Exception as e:
        logger.error(f"❌ Database connection failed: {e}")
        return False
    return False

# Initialize database connection
db = Database()

# Initialize DAOs
tenant_dao = TenantDAO(db)
playbook_dao = PlaybookDAO(db)
execution_dao = ExecutionDAO(db)
ioc_dao = IOCDAO(db)
detection_dao = DetectionDAO(db)