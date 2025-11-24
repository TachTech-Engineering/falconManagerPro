from functools import wraps
from flask import request, jsonify, g
import logging
from database import tenant_dao

logger = logging.getLogger(__name__)


def require_tenant(f):
    """
    Decorator to require valid tenant authentication via API key.
    Extracts tenant from X-API-Key header and stores in Flask g object.
    
    Usage:
        @app.route('/api/playbooks')
        @require_tenant
        def get_playbooks():
            tenant_id = g.tenant['id']
            # ... your code
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Get API key from header
        api_key = request.headers.get('X-API-Key')
        
        if not api_key:
            logger.warning("Missing X-API-Key header")
            return jsonify({
                'error': 'Missing authentication',
                'message': 'X-API-Key header is required'
            }), 401
        
        # Look up tenant
        try:
            tenant = tenant_dao.get_by_api_key(api_key)
            
            if not tenant:
                logger.warning(f"Invalid API key attempted: {api_key[:10]}...")
                return jsonify({
                    'error': 'Invalid API key',
                    'message': 'The provided API key is invalid or inactive'
                }), 401
            
            # Check if tenant has trial expired
            if tenant.get('trial_ends_at'):
                from datetime import datetime
                if datetime.now() > tenant['trial_ends_at']:
                    logger.warning(f"Expired trial for tenant: {tenant['id']}")
                    return jsonify({
                        'error': 'Trial expired',
                        'message': 'Your trial period has ended. Please upgrade your plan.'
                    }), 403
            
            # Store tenant in Flask g object for use in route
            g.tenant = tenant
            g.tenant_id = tenant['id']
            
            logger.info(f"Authenticated request for tenant: {tenant['name']} ({tenant['id']})")
            
        except Exception as e:
            logger.error(f"Error during authentication: {e}")
            return jsonify({
                'error': 'Authentication error',
                'message': 'An error occurred during authentication'
            }), 500
        
        return f(*args, **kwargs)
    
    return decorated_function


def require_plan(required_plan: str):
    """
    Decorator to require specific plan level.
    Must be used after @require_tenant decorator.
    
    Plans (in order): free, basic, pro, enterprise
    
    Usage:
        @app.route('/api/advanced-feature')
        @require_tenant
        @require_plan('pro')
        def advanced_feature():
            # Only accessible to pro and enterprise plans
    """
    plan_hierarchy = {
        'free': 0,
        'basic': 1,
        'pro': 2,
        'enterprise': 3
    }
    
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'tenant'):
                return jsonify({
                    'error': 'Authentication required',
                    'message': 'This endpoint requires authentication'
                }), 401
            
            tenant_plan = g.tenant.get('plan', 'free')
            
            tenant_level = plan_hierarchy.get(tenant_plan, 0)
            required_level = plan_hierarchy.get(required_plan, 0)
            
            if tenant_level < required_level:
                logger.warning(
                    f"Insufficient plan level for tenant {g.tenant['id']}: "
                    f"has {tenant_plan}, needs {required_plan}"
                )
                return jsonify({
                    'error': 'Insufficient plan',
                    'message': f'This feature requires {required_plan} plan or higher',
                    'current_plan': tenant_plan,
                    'required_plan': required_plan
                }), 403
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator


def check_resource_limit(resource_type: str):
    """
    Decorator to check if tenant has reached resource limits.
    Must be used after @require_tenant decorator.
    
    Usage:
        @app.route('/api/playbooks', methods=['POST'])
        @require_tenant
        @check_resource_limit('playbooks')
        def create_playbook():
            # Will be blocked if max_playbooks reached
    """
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not hasattr(g, 'tenant'):
                return jsonify({
                    'error': 'Authentication required'
                }), 401
            
            tenant = g.tenant
            
            # Check resource limits based on type
            if resource_type == 'playbooks':
                from database import playbook_dao
                current_count = len(playbook_dao.get_all(tenant['id']))
                max_allowed = tenant.get('max_playbooks', 10)
                
                if current_count >= max_allowed:
                    return jsonify({
                        'error': 'Resource limit reached',
                        'message': f'Maximum playbooks limit reached ({max_allowed})',
                        'current': current_count,
                        'limit': max_allowed
                    }), 403
            
            elif resource_type == 'users':
                # Implement user count check if needed
                max_allowed = tenant.get('max_users', 5)
                # current_count = ... (implement user counting)
                pass
            
            return f(*args, **kwargs)
        
        return decorated_function
    
    return decorator


def log_api_call(f):
    """
    Decorator to log API calls for auditing.
    Should be used after @require_tenant decorator.
    
    Usage:
        @app.route('/api/sensitive-endpoint')
        @require_tenant
        @log_api_call
        def sensitive_endpoint():
            # API call will be logged
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        tenant_id = getattr(g, 'tenant_id', 'unknown')
        tenant_name = getattr(g, 'tenant', {}).get('name', 'unknown')
        
        logger.info(
            f"API Call | Tenant: {tenant_name} ({tenant_id}) | "
            f"Endpoint: {request.method} {request.path} | "
            f"IP: {request.remote_addr}"
        )
        
        return f(*args, **kwargs)
    
    return decorated_function


def get_tenant_credentials():
    """
    Helper function to get tenant's CrowdStrike credentials.
    Must be called within a request context with @require_tenant decorator.
    
    Returns:
        tuple: (client_id, client_secret, base_url) or None if not configured
    """
    if not hasattr(g, 'tenant'):
        return None
    
    tenant = g.tenant
    
    client_id = tenant.get('crowdstrike_client_id')
    client_secret = tenant.get('crowdstrike_client_secret')
    base_url = tenant.get('crowdstrike_base_url', 'https://api.crowdstrike.com')
    
    if not client_id or not client_secret:
        logger.warning(f"Tenant {tenant['id']} missing CrowdStrike credentials")
        return None
    
    return client_id, client_secret, base_url


def get_virustotal_key():
    """
    Helper function to get tenant's VirusTotal API key.
    Must be called within a request context with @require_tenant decorator.
    
    Returns:
        str: VirusTotal API key or None if not configured
    """
    if not hasattr(g, 'tenant'):
        return None
    
    tenant = g.tenant
    vt_key = tenant.get('virustotal_api_key')
    
    if not vt_key:
        logger.warning(f"Tenant {tenant['id']} missing VirusTotal API key")
    
    return vt_key