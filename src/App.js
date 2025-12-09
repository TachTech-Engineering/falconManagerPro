import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle, Shield, Activity, Server, Search, RefreshCw,
  AlertCircle, Download, Plus, Play, Trash2, HelpCircle, X, Book, LogOut, Moon, Sun,
  Clock, TrendingUp, CheckSquare, Zap, BookOpen, Terminal, Database, Hash, Globe,
  List, CheckCircle, Lightbulb, ExternalLink, Command, Copy, Check
} from 'lucide-react';

// Import MITRE ATT&CK utilities
import { 
  mapToMitreAttack, 
  MitreTechniqueBadge, 
  MitreTacticBadge, 
  MitreAttackMatrix
} from './utils/mitreAttack';

const API_BASE = '/api';

// Multi-Tenancy Auth Helper
const getAuthHeaders = () => {
  const headers = { 'Content-Type': 'application/json' };
  const sessionToken = sessionStorage.getItem('falcon_session_token');
  if (sessionToken) headers['X-Session-Token'] = sessionToken;
  return headers;
};

const FalconDashboard = () => {
  // ============================================================================
  // STATE DECLARATIONS
  // ============================================================================  
  // Dark Mode State
  const [darkMode, setDarkMode] = useState(() => {
    const saved = localStorage.getItem('falcon_dark_mode');
    return saved === 'true' || (saved === null && window.matchMedia('(prefers-color-scheme: dark)').matches);
  });
  
  // Apply dark mode class to document
  useEffect(() => {
    if (darkMode) {
      document.documentElement.classList.add('dark');
    } else {
      document.documentElement.classList.remove('dark');
    }
    localStorage.setItem('falcon_dark_mode', darkMode.toString());
  }, [darkMode]);
  
  const toggleDarkMode = () => setDarkMode(prev => !prev);
  
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(() => 
    sessionStorage.getItem('falcon_session_token') !== null
  );

  const [credentials, setCredentials] = useState({
    clientId: '', clientSecret: '', baseUrl: 'https://api.crowdstrike.com', vtApiKey: ''
  });
  const [tenantInfo, setTenantInfo] = useState(null);
  const [detections, setDetections] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [iocs, setIOCs] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [dashboardStats, setDashboardStats] = useState(null);
  const [nonHashDetections, setNonHashDetections] = useState(0);
  const [timeRange, setTimeRange] = useState('24');
  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedDetections, setSelectedDetections] = useState([]);
  const [notification, setNotification] = useState(null);
  const [showCommentDialog, setShowCommentDialog] = useState(false);
  const [commentData, setCommentData] = useState({ detectionId: null, action: '', comment: '' });
  const [showIOCDialog, setShowIOCDialog] = useState(false);
  const [showPlaybookDialog, setShowPlaybookDialog] = useState(false);
  const [showExecuteDialog, setShowExecuteDialog] = useState(false);
  const [executePlaybook, setExecutePlaybook] = useState(null);
  const [showRTROutputDialog, setShowRTROutputDialog] = useState(false);
  const [rtrOutput, setRTROutput] = useState(null);
  const [showHashDialog, setShowHashDialog] = useState(false);
  const [showHashAnalysisDialog, setShowHashAnalysisDialog] = useState(false);
  const [showAdvancedSearchDialog, setShowAdvancedSearchDialog] = useState(false);
  const [showExclusionDialog, setShowExclusionDialog] = useState(false);
  const [hashAnalysis, setHashAnalysis] = useState(null);
  const [vtData, setVTData] = useState({});
  const [vtLoading, setVTLoading] = useState({});
  const [showHelpSidebar, setShowHelpSidebar] = useState(false);
  const [showReportDialog, setShowReportDialog] = useState(false);
  const [preselectedHash, setPreselectedHash] = useState('');
  const [showHashToolsDropdown, setShowHashToolsDropdown] = useState(false);
  const [showSystemDropdown, setShowSystemDropdown] = useState(false);
  const [autoTriggerStatus, setAutoTriggerStatus] = useState(null);
  const [platformFilter, setPlatformFilter] = useState('all');
  const [isRefreshing, setIsRefreshing] = useState(false);

  const showNotification = useCallback((message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  }, []);

  const openRTROutput = (title, data) => {
    setRTROutput({ title, data });
    setShowRTROutputDialog(true);
  };

  // ============================================================================
  // AUTHENTICATION
  // ============================================================================
  const handleLogin = async () => {
    if (!credentials.clientId || !credentials.clientSecret) {
      showNotification('Please enter Client ID and Client Secret', 'error');
      return;
    }
    try {
      const response = await fetch(`${API_BASE}/auth`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          client_id: credentials.clientId,
          client_secret: credentials.clientSecret,
          base_url: credentials.baseUrl,
        }),
      });
      const data = await response.json();
      if (data.status === 'success' && data.session_token) {
        sessionStorage.setItem('falcon_session_token', data.session_token);
        if (data.tenant) {
          setTenantInfo(data.tenant);
          sessionStorage.setItem('falcon_tenant', JSON.stringify(data.tenant));
        }
        if (credentials.vtApiKey) {
          sessionStorage.setItem('falcon_vt_key', credentials.vtApiKey);
        }
        setIsAuthenticated(true);
        showNotification(`Welcome! Logged in as ${data.tenant?.name || 'User'}`);
        fetchAllData();
      } else {
        showNotification(data.message || 'Authentication failed', 'error');
      }
    } catch (error) {
      showNotification('Error connecting to backend: ' + error.message, 'error');
    }
  };

  const handleLogout = async () => {
    try {
      await fetch(`${API_BASE}/session/logout`, {
        method: 'POST', headers: getAuthHeaders()
      });
    } catch (error) {
      console.error('Error during logout:', error);
    } finally {
      sessionStorage.removeItem('falcon_session_token');
      sessionStorage.removeItem('falcon_tenant');
      sessionStorage.removeItem('falcon_vt_key');
      setIsAuthenticated(false);
      setTenantInfo(null);
      showNotification('Logged out successfully');
    }
  };

  const handleApiError = useCallback((response) => {
    if (response.status === 401) {
      sessionStorage.removeItem('falcon_session_token');
      sessionStorage.removeItem('falcon_tenant');
      setIsAuthenticated(false);
      showNotification('Session expired - please login again', 'error');
      return true;
    }
    return false;
  }, [showNotification]);

  // ============================================================================
  // DATA FETCHING
  // ============================================================================
  const fetchDetections = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/detections?hours=${timeRange}`, { 
        headers: getAuthHeaders() 
      });
      if (handleApiError(response)) return;
      const data = await response.json();
      if (data.detections) {
        setDetections(data.detections);
        
        if (data.source === 'database') {
          console.log(`📊 Loaded ${data.count} detections from database`);
        } else {
          console.log(`🔴 Loaded ${data.count} detections from CrowdStrike API`);
        }
        
        const nonHash = data.detections.filter(d => {
          if (d.has_hash !== undefined) return !d.has_hash;
          const allText = `${d.name || ''} ${d.behavior || ''} ${d.description || ''}`.toLowerCase();
          return !['hash', 'sha256', 'sha1', 'md5'].some(kw => allText.includes(kw));
        }).length;
        setNonHashDetections(nonHash);
      }
    } catch (error) {
      console.error('Error fetching detections:', error);
    }
  }, [handleApiError, timeRange]);

  const fetchHosts = useCallback(async (forceRefresh = false) => {
    try {
      const params = new URLSearchParams();
      if (forceRefresh) params.append('force_refresh', 'true');
      const response = await fetch(`${API_BASE}/hosts?${params}`, { headers: getAuthHeaders() });
      if (handleApiError(response)) return;
      if (!response.ok) {
        const errorData = await response.json().catch(() => ({ error: 'Unknown error' }));
        showNotification(`Failed to fetch hosts: ${errorData.error}`, 'error');
        setHosts([]);
        return;
      }
      const data = await response.json();
      if (data.hosts) setHosts(data.hosts);
    } catch (error) {
      console.error('Error fetching hosts:', error);
      showNotification(`Error fetching hosts: ${error.message}`, 'error');
    }
  }, [handleApiError, showNotification]);

  const fetchIOCs = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/iocs`, { headers: getAuthHeaders() });
      if (handleApiError(response)) return;
      if (response.status === 403 || response.status === 500) {
        setIOCs([]);
        return;
      }
      const data = await response.json();
      if (data.iocs) setIOCs(data.iocs);
    } catch (error) {
      console.error('Error fetching IOCs:', error);
      setIOCs([]);
    }
  }, [handleApiError]);

  const fetchPlaybooks = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/playbooks`, { headers: getAuthHeaders() });
      if (handleApiError(response)) return;
      const data = await response.json();
      if (data.playbooks) setPlaybooks(data.playbooks);
    } catch (error) {
      console.error('Error fetching playbooks:', error);
    }
  }, [handleApiError]);

  const calculateDashboardStats = (detections, hours) => {
    const now = new Date();

    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      informational: 0,
      unknown: 0,
    };

    const statusCounts = {
      new: 0,
      in_progress: 0,
      true_positive: 0,
      false_positive: 0,
      closed: 0,
      ignored: 0,
    };

    // 🔑 Normalize ANY severity (string or number) into our buckets
    const normalizeSeverity = (sev) => {
      if (sev == null) return 'unknown';

      const s = String(sev).toLowerCase();
      const n = Number(s);

      // Numeric CrowdStrike values
      if (!Number.isNaN(n)) {
          if (n <= 19) return 'informational';  // 0–19
          if (n <= 39) return 'low';            // 20–39
          if (n <= 59) return 'medium';         // 40–59
          if (n <= 79) return 'high';           // 60–79
          return 'critical';                    // 80–100+
      }

      // String-based severities
      if (s === 'info') return 'informational';
      if (['critical','high','medium','low','informational','unknown'].includes(s)) {
        return s;
      }

      return 'unknown';
    };


    let bucketCount, bucketSizeHours, bucketLabel;

    if (hours <= 24) {
      bucketCount = hours;
      bucketSizeHours = 1;
      bucketLabel = (bucket) => `${bucket.hour}:00`;
    } else if (hours <= 168) {
      bucketCount = Math.ceil(hours / 4);
      bucketSizeHours = 4;
      bucketLabel = (bucket) => {
        const date = new Date(bucket.time);
        const hour = date.getHours();
        return `${date.getMonth() + 1}/${date.getDate()} ${hour}:00`;
      };
    } else {
      bucketCount = Math.ceil(hours / 24);
      bucketSizeHours = 24;
      bucketLabel = (bucket) => {
        const date = new Date(bucket.time);
        return `${date.getMonth() + 1}/${date.getDate()}`;
      };
    }

    const timelineData = [];

    // Build buckets from oldest → newest
    for (let i = bucketCount - 1; i >= 0; i--) {
      const bucketTime = new Date(now.getTime() - i * bucketSizeHours * 60 * 60 * 1000);
      const hour = bucketTime.getHours();
      timelineData.push({
        time: bucketTime,
        hour,
        label: bucketLabel({ time: bucketTime, hour }),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        informational: 0,
        unknown: 0,
        total: 0,
      });
    }

    // Walk detections and populate counts + buckets
    detections.forEach((det) => {
      const severity = normalizeSeverity(det.severity);
      const status = (det.status || 'new').toLowerCase();

      // Severity tile counts
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;
      statusCounts[status] = (statusCounts[status] || 0) + 1;

      // Timeline buckets
      if (det.timestamp) {
        const detTime = new Date(det.timestamp);
        const timeSinceDetection = (now - detTime) / (60 * 60 * 1000); // hours

        if (timeSinceDetection >= 0 && timeSinceDetection < hours) {
          const bucketIndex = Math.floor(timeSinceDetection / bucketSizeHours);
          const timelineBucket = timelineData[timelineData.length - 1 - bucketIndex];

          if (timelineBucket && Object.prototype.hasOwnProperty.call(timelineBucket, severity)) {
            timelineBucket[severity] += 1;
            timelineBucket.total += 1;
          }
        }
      }
    });

    return {
      severityCounts,
      statusCounts,
      timelineData,
      totalDetections: detections.length,
      bucketSizeHours,
    };
  };


    const fetchDashboardStats = useCallback(() => {
      try {
        if (!detections || detections.length === 0) {
          setDashboardStats(null);
          return;
        }

        const hours = parseInt(timeRange, 10) || 24;
        const stats = calculateDashboardStats(detections, hours);
        setDashboardStats(stats);

      } catch (error) {
        console.error('Error calculating dashboard stats:', error);
      }
    }, [detections, timeRange]);


    const fetchVirusTotalData = async (hash) => {
      const vtApiKey = sessionStorage.getItem('falcon_vt_key');
      if (!vtApiKey) {
        setVTData(prev => ({ ...prev, [hash]: { error: 'VirusTotal API key not configured' } }));
        return;
      }
      
      setVTLoading(prev => ({ ...prev, [hash]: true }));
      try {
        const response = await fetch(`${API_BASE}/virustotal/hash/${hash}`, {
          headers: { ...getAuthHeaders(), 'X-VT-API-Key': vtApiKey }
        });
        if (handleApiError(response)) return;
        
        if (response.ok) {
          const data = await response.json();
          setVTData(prev => ({ ...prev, [hash]: data }));
        } else {
          const errorData = await response.json();
          setVTData(prev => ({ ...prev, [hash]: { error: errorData.error || 'Failed to fetch VT data' } }));
        }
      } catch (error) {
        console.error('Error fetching VirusTotal data:', error);
        setVTData(prev => ({ ...prev, [hash]: { error: 'Error fetching VT data' } }));
      } finally {
        setVTLoading(prev => ({ ...prev, [hash]: false }));
      }
    };

    const fetchAutoTriggerStatus = useCallback(async () => {
      try {
        const response = await fetch(`${API_BASE}/playbooks/auto-trigger/status`, { headers: getAuthHeaders() });
        if (handleApiError(response)) return;
        const data = await response.json();
        setAutoTriggerStatus(data);
      } catch (error) {
        console.error('Error fetching auto-trigger status:', error);
      }
    }, [handleApiError]);

    const fetchAllData = useCallback(() => {
      if (!isAuthenticated) return;

      fetchDetections();
      fetchHosts(false);
      fetchIOCs();
      fetchPlaybooks();

      if (activeTab === 'playbooks') {
        fetchAutoTriggerStatus();
      }
    }, [
      isAuthenticated,
      fetchDetections,
      fetchHosts,
      fetchIOCs,
      fetchPlaybooks,
      fetchAutoTriggerStatus,
      activeTab,
    ]);


    useEffect(() => {
  if (!isAuthenticated) return;

  // Initial load
  fetchDetections();
  fetchHosts(false);
  fetchIOCs();
  fetchPlaybooks();

  // Poll every 30 seconds
  const interval = setInterval(() => {
    fetchDetections();
    fetchHosts(false);
  }, 30000);

  return () => clearInterval(interval);

}, [isAuthenticated, fetchDetections, fetchHosts, fetchIOCs, fetchPlaybooks]);

  useEffect(() => {
    if (!isAuthenticated) return;
    fetchDashboardStats();
  }, [isAuthenticated, detections, timeRange, fetchDashboardStats]);

  useEffect(() => {
  if (detections && detections.length) {
    const bySeverity = detections.reduce((acc, d) => {
      const sev = d.severity || '(empty)';
      acc[sev] = (acc[sev] || 0) + 1;
      return acc;
    }, {});
    console.log('Detections by severity from API:', bySeverity);
  }
}, [detections]);


  // ============================================================================
  // DETECTION ACTIONS
  // ============================================================================
  const openCommentDialog = (detectionId, action) => {
    setCommentData({ detectionId, action, comment: '' });
    setShowCommentDialog(true);
  };

  const handleDetectionAction = async () => {
    const { detectionId, action, comment } = commentData;
    try {
      let endpoint = '';
      const body = { comment };
      
      if (action === 'resolve') {
        endpoint = `/detections/${detectionId}/status`;
        body.status = 'true_positive';
      } else if (action === 'close_fp') {
        endpoint = `/detections/${detectionId}/status`;
        body.status = 'false_positive';
      } else if (action === 'ignore') {
        endpoint = `/detections/${detectionId}/status`;
        body.status = 'ignored';
      }
      
      const response = await fetch(`${API_BASE}${endpoint}`, {
        method: 'PATCH',
        headers: getAuthHeaders(),
        body: JSON.stringify(body),
      });
      if (handleApiError(response)) return;
      
      if (response.ok) {
        setShowCommentDialog(false);
        fetchDetections();
        showNotification('Detection updated successfully');
      } else {
        showNotification('Failed to update detection', 'error');
      }
    } catch (error) {
      console.error('Error updating detection:', error);
    }
  };

  const handleBulkUpdate = async (status) => {
    if (selectedDetections.length === 0) {
      showNotification('Please select detections first', 'error');
      return;
    }
    const comment = prompt('Enter comment for bulk update:');
    if (!comment) return;
    
    try {
      const response = await fetch(`${API_BASE}/detections/bulk-update`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ detection_ids: selectedDetections, status, comment }),
      });
      if (handleApiError(response)) return;
      
      if (response.ok) {
        const count = selectedDetections.length;
        setSelectedDetections([]);
        fetchDetections();
        showNotification(`${count} detections updated successfully`);
      } else {
        showNotification('Failed to update detections', 'error');
      }
    } catch (error) {
      console.error('Error in bulk update:', error);
    }
  };

  const toggleDetectionSelection = (detectionId) => {
    setSelectedDetections((prev) =>
      prev.includes(detectionId) ? prev.filter((id) => id !== detectionId) : [...prev, detectionId]
    );
  };

  // ============================================================================
  // IOC ACTIONS
  // ============================================================================
  const handleCreateIOC = async (iocData) => {
    try {
      const response = await fetch(`${API_BASE}/iocs`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(iocData)
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        setShowIOCDialog(false);
        fetchIOCs();
        showNotification('IOC created successfully');
      } else {
        showNotification('Failed to create IOC', 'error');
      }
    } catch (error) {
      console.error('Error creating IOC:', error);
    }
  };

  const handleDeleteIOC = async (iocId) => {
    if (!window.confirm('Are you sure you want to delete this IOC?')) return;
    try {
      const response = await fetch(`${API_BASE}/iocs/${iocId}`, {
        method: 'DELETE', headers: getAuthHeaders()
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        fetchIOCs();
        showNotification('IOC deleted successfully');
      } else {
        showNotification('Failed to delete IOC', 'error');
      }
    } catch (error) {
      console.error('Error deleting IOC:', error);
    }
  };

  // ============================================================================
  // PLAYBOOK ACTIONS
  // ============================================================================
  const handleCreatePlaybook = async (playbookData) => {
    try {
      const response = await fetch(`${API_BASE}/playbooks`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(playbookData)
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        setShowPlaybookDialog(false);
        fetchPlaybooks();
        showNotification('Playbook created successfully');
      } else {
        showNotification('Failed to create playbook', 'error');
      }
    } catch (error) {
      console.error('Error creating playbook:', error);
    }
  };

  const handleDeletePlaybook = async (playbookId) => {
    if (!window.confirm('Are you sure you want to delete this playbook?')) return;
    try {
      const response = await fetch(`${API_BASE}/playbooks/${playbookId}`, {
        method: 'DELETE', headers: getAuthHeaders()
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        fetchPlaybooks();
        showNotification('Playbook deleted successfully');
      } else {
        const errorData = await response.json().catch(() => ({}));
        showNotification(errorData.error || 'Failed to delete playbook', 'error');
      }
    } catch (error) {
      console.error('Error deleting playbook:', error);
    }
  };

  const handleExecutePlaybook = async (playbookId, targetType, targetId) => {
    if (!targetId) {
      showNotification('Please select a target', 'error');
      return;
    }

    try {
      const response = await fetch(`${API_BASE}/playbooks/${playbookId}/execute`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ target_type: targetType, target_id: targetId }),
      });
      if (handleApiError(response)) return;

      if (response.ok) {
        const data = await response.json();
        const successCount = data.results?.filter(r => r.status === 'success').length ?? 0;
        showNotification(`Playbook executed (${successCount} actions successful)`);
        setShowExecuteDialog(false);
      } else {
        showNotification('Failed to execute playbook', 'error');
      }
    } catch (error) {
      console.error('Error executing playbook:', error);
    }
  };

  const openExecuteDialog = (playbook) => {
    setExecutePlaybook(playbook);
    setShowExecuteDialog(true);
  };

  const toggleAutoTrigger = async () => {
    try {
      const response = await fetch(`${API_BASE}/playbooks/auto-trigger/toggle`, {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({ enabled: !autoTriggerStatus.enabled })
      });
      if (handleApiError(response)) return;
      const data = await response.json();
      setAutoTriggerStatus({ ...autoTriggerStatus, enabled: data.enabled });
      showNotification(`Auto-trigger ${data.enabled ? 'enabled' : 'disabled'}`);
    } catch (error) {
      showNotification('Failed to toggle auto-trigger', 'error');
    }
  };

  // ============================================================================
  // HOST ACTIONS - ALL RTR COMMANDS (ALL 3 TIERS)
  // ============================================================================
  const handleContainHost = async (hostId) => {
    if (!window.confirm('Are you sure you want to network contain this host?')) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/contain`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      if (!res.ok) {
        showNotification('Failed to contain host', 'error');
        return;
      }
      showNotification('Host contained successfully');
      fetchHosts();
    } catch (err) {
      console.error('Error in handleContainHost:', err);
      showNotification('Error containing host', 'error');
    }
  };

  const handleLiftContainment = async (hostId) => {
    if (!window.confirm('Are you sure you want to lift containment?')) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/lift-containment`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      if (!res.ok) {
        showNotification('Failed to lift containment', 'error');
        return;
      }
      showNotification('Containment lifted successfully');
      fetchHosts();
    } catch (err) {
      console.error('Error in handleLiftContainment:', err);
      showNotification('Error lifting containment', 'error');
    }
  };

  const handleKillProcess = async (hostId) => {
    const processName = window.prompt(`Enter the process name or PID to kill on host ${hostId}:`);
    if (!processName) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/kill`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ process: processName })
      });
      if (handleApiError(res)) return;
      if (!res.ok) {
        showNotification('Failed to send kill command', 'error');
        return;
      }
      showNotification('RTR kill command sent');
    } catch (err) {
      console.error('Error in handleKillProcess:', err);
      showNotification('Error sending RTR kill command', 'error');
    }
  };

  const handleDeleteFile = async (hostId) => {
    const filePath = window.prompt(`Enter the full path of the file to delete on host ${hostId}:`);
    if (!filePath) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/delete-file`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path: filePath })
      });
      if (handleApiError(res)) return;
      if (!res.ok) {
        showNotification('Failed to send delete-file command', 'error');
        return;
      }
      showNotification('RTR delete-file command sent');
    } catch (err) {
      console.error('Error in handleDeleteFile:', err);
      showNotification('Error sending RTR delete-file command', 'error');
    }
  };

  // RTR Tier 1 Commands (Read-Only)
  const handleRTRFileHash = async (hostId) => {
    const path = window.prompt(`Enter full file path to hash on host ${hostId}:`);
    if (!path) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/filehash`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to run filehash', 'error');
      openRTROutput(`Filehash on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRFileHash:', err);
      showNotification('Error running filehash', 'error');
    }
  };

  const handleRTRLs = async (hostId) => {
    const path = window.prompt(`Enter directory path to list on host ${hostId}:`, 'C:\\');
    if (!path) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/ls`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to run ls', 'error');
      openRTROutput(`Directory listing (${path}) on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRLs:', err);
      showNotification('Error running ls', 'error');
    }
  };

  const handleRTRNetstat = async (hostId) => {
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/netstat`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to run netstat', 'error');
      openRTROutput(`Netstat on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRNetstat:', err);
      showNotification('Error running netstat', 'error');
    }
  };

  const handleRTRPs = async (hostId) => {
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/ps`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to list processes', 'error');
      openRTROutput(`Processes on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRPs:', err);
      showNotification('Error listing processes', 'error');
    }
  };

  // RTR Tier 2 Commands (Active Responder)
  const handleRTRRegQuery = async (hostId) => {
    const key = window.prompt(`Enter registry key/path to query on host ${hostId}:`);
    if (!key) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/reg-query`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ key })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to query registry', 'error');
      openRTROutput(`Registry query on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRRegQuery:', err);
      showNotification('Error querying registry', 'error');
    }
  };

  const handleRTRGetFile = async (hostId) => {
    const path = window.prompt(`Enter full file path to retrieve from host ${hostId}:`);
    if (!path) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/get-file`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path })
      });
      if (handleApiError(res)) return;
      if (!res.ok) {
        showNotification('Failed to request file', 'error');
        return;
      }
      const data = await res.json().catch(() => ({}));
      openRTROutput(`Get file from ${hostId}`, data);
      showNotification('File collection initiated');
    } catch (err) {
      console.error('Error in handleRTRGetFile:', err);
      showNotification('Error requesting file', 'error');
    }
  };

  const handleRTRMemdump = async (hostId) => {
    const pid = window.prompt(`Enter PID to dump memory from (blank for full system) on host ${hostId}:`, '');
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/memdump`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(pid ? { pid } : {})
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to initiate memdump', 'error');
      openRTROutput(`Memdump on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRMemdump:', err);
      showNotification('Error initiating memdump', 'error');
    }
  };

  const handleRTRCp = async (hostId) => {
    const source = window.prompt(`Enter source path on host ${hostId}:`);
    if (!source) return;
    const destination = window.prompt(`Enter destination path on host ${hostId}:`);
    if (!destination) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/cp`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ source, destination })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to copy file', 'error');
      openRTROutput(`Copy file on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRCp:', err);
      showNotification('Error copying file', 'error');
    }
  };

  const handleRTRZip = async (hostId) => {
    const path = window.prompt(`Enter file/folder path to zip on host ${hostId}:`);
    if (!path) return;
    const dest = window.prompt(`Enter destination zip path on host ${hostId}:`, `${path}.zip`);
    if (!dest) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/zip`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path, destination: dest })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to zip path', 'error');
      openRTROutput(`Zip on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRZip:', err);
      showNotification('Error zipping path', 'error');
    }
  };

  // RTR Tier 3 Commands (Admin)
  const handleRTRListScripts = async () => {
    try {
      const res = await fetch(`${API_BASE}/rtr/scripts`, { headers: getAuthHeaders() });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to list scripts', 'error');
      openRTROutput('RTR Scripts', data);
    } catch (err) {
      console.error('Error in handleRTRListScripts:', err);
      showNotification('Error listing scripts', 'error');
    }
  };

  const handleRTRRunScript = async (hostId) => {
    const scriptName = window.prompt(`Enter script name/ID to run on host ${hostId}:`);
    if (!scriptName) return;
    const args = window.prompt('Enter arguments (space separated) or leave blank:', '');
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/runscript`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ script: scriptName, args })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to run script', 'error');
      openRTROutput(`Run script on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRRunScript:', err);
      showNotification('Error running script', 'error');
    }
  };

  const handleRTRPutFile = async (hostId) => {
    const remotePath = window.prompt(`Enter destination path on host ${hostId}:`);
    if (!remotePath) return;
    const description = window.prompt('Enter description / logical file name:', '');
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/put-file`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ path: remotePath, description })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to put file', 'error');
      openRTROutput(`Put file on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRPutFile:', err);
      showNotification('Error putting file', 'error');
    }
  };

  const handleRTRRegDelete = async (hostId) => {
    const key = window.prompt(`Enter registry key/path to DELETE on host ${hostId}:`);
    if (!key) return;
    if (!window.confirm(`Are you sure you want to delete registry key/value:\n${key}\n\nHost: ${hostId}`)) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/reg-delete`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ key })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to delete registry key', 'error');
      openRTROutput(`Registry delete on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRRegDelete:', err);
      showNotification('Error deleting registry key', 'error');
    }
  };

  const handleRTRRegSet = async (hostId) => {
    const key = window.prompt(`Enter registry key/path to SET on host ${hostId}:`);
    if (!key) return;
    const value = window.prompt('Enter value:');
    if (value === null) return;
    const type = window.prompt('Enter registry type (e.g. REG_SZ, REG_DWORD):', 'REG_SZ') || 'REG_SZ';
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/reg-set`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ key, value, type })
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to set registry value', 'error');
      openRTROutput(`Registry set on ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRRegSet:', err);
      showNotification('Error setting registry value', 'error');
    }
  };

  const handleRTRRestart = async (hostId) => {
    if (!window.confirm(`Restart host ${hostId}?`)) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/restart`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showNotification('Failed to restart host', 'error');
      } else {
        showNotification('Restart command sent');
      }
      openRTROutput(`Restart host ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRRestart:', err);
      showNotification('Error restarting host', 'error');
    }
  };

  const handleRTRShutdown = async (hostId) => {
    if (!window.confirm(`SHUTDOWN host ${hostId}? This will power it off.`)) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/shutdown`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showNotification('Failed to shutdown host', 'error');
      } else {
        showNotification('Shutdown command sent');
      }
      openRTROutput(`Shutdown host ${hostId}`, data);
    } catch (err) {
      console.error('Error in handleRTRShutdown:', err);
      showNotification('Error shutting down host', 'error');
    }
  };

  // ============================================================================
  // HASH TOOLS
  // ============================================================================
  const handleCloseByHash = async (hashData) => {
    try {
      const response = await fetch(`${API_BASE}/detections/close-by-hash`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(hashData)
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        const result = await response.json();
        setShowHashDialog(false);
        showNotification(`Closed ${result.success} detections for hash`);
        fetchDetections();
      } else {
        showNotification('Failed to close by hash', 'error');
      }
    } catch (error) {
      console.error('Error closing by hash:', error);
    }
  };

  const handleHashAnalysis = async () => {
    try {
      const response = await fetch(`${API_BASE}/detections/hash-summary?filter=status:"new"&limit=10000`, {
        headers: getAuthHeaders()
      });
      if (handleApiError(response)) return;
      const data = await response.json();
      if (response.ok) {
        setHashAnalysis(data);
        setShowHashAnalysisDialog(true);
      } else {
        showNotification('Failed to fetch hash analysis', 'error');
      }
    } catch (error) {
      console.error('Error fetching hash analysis:', error);
    }
  };

  const handleAdvancedSearch = async (filterString) => {
    try {
      const response = await fetch(`${API_BASE}/detections/advanced-search`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify({ filter: filterString, limit: 100 })
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        const data = await response.json();
        setDetections(data.detections);
        setShowAdvancedSearchDialog(false);
        showNotification(`Found ${data.count} detections`);
      } else {
        showNotification('Advanced search failed', 'error');
      }
    } catch (error) {
      console.error('Error in advanced search:', error);
    }
  };

  const handleCreateExclusion = async (exclusionData) => {
    try {
      const response = await fetch(`${API_BASE}/iocs/create-exclusion`, {
        method: 'POST', headers: getAuthHeaders(), body: JSON.stringify(exclusionData)
      });
      if (handleApiError(response)) return;
      if (response.ok) {
        setShowExclusionDialog(false);
        showNotification('IOC exclusion created successfully');
      } else {
        showNotification('Failed to create exclusion', 'error');
      }
    } catch (error) {
      console.error('Error creating exclusion:', error);
    }
  };

  // ============================================================================
  // SYSTEM TOOLS
  // ============================================================================
  const handleHealthCheck = async () => {
    try {
      const res = await fetch(`${API_BASE}/health`, { headers: getAuthHeaders() });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Health check failed', 'error');
      openRTROutput('API Health', data);
    } catch (err) {
      console.error('Error in handleHealthCheck:', err);
      showNotification('Error checking health', 'error');
    }
  };

  const handleCacheInfo = async () => {
    try {
      const res = await fetch(`${API_BASE}/cache/info`, { headers: getAuthHeaders() });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Failed to get cache info', 'error');
      openRTROutput('Cache Info', data);
    } catch (err) {
      console.error('Error in handleCacheInfo:', err);
      showNotification('Error getting cache info', 'error');
    }
  };

  const handleCacheClear = async () => {
    if (!window.confirm('Clear API cache?')) return;
    try {
      const res = await fetch(`${API_BASE}/cache/clear`, {
        method: 'POST', headers: getAuthHeaders()
      });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) {
        showNotification('Failed to clear cache', 'error');
      } else {
        showNotification('Cache cleared');
      }
      openRTROutput('Cache Clear', data);
    } catch (err) {
      console.error('Error in handleCacheClear:', err);
      showNotification('Error clearing cache', 'error');
    }
  };

  const handleDebugHostsTest = async () => {
    try {
      const res = await fetch(`${API_BASE}/debug/hosts-test`, { headers: getAuthHeaders() });
      if (handleApiError(res)) return;
      const data = await res.json().catch(() => ({}));
      if (!res.ok) showNotification('Debug hosts-test failed', 'error');
      openRTROutput('Debug Hosts Test', data);
    } catch (err) {
      console.error('Error in handleDebugHostsTest:', err);
      showNotification('Error running debug hosts-test', 'error');
    }
  };

  const handleApiIndex = async () => {
    try {
      const res = await fetch(`${API_BASE}/info`, { headers: getAuthHeaders() });
      if (handleApiError(res)) return;
      if (!res.ok) throw new Error(`HTTP ${res.status}: ${res.statusText}`);
      const data = await res.json();
      openRTROutput('API Documentation', data);
    } catch (err) {
      console.error('Error in handleApiIndex:', err);
      showNotification(`Error loading API docs: ${err.message}`, 'error');
    }
  };

  const handleGenerateReport = async (reportConfig) => {
      try {
        const payload = {
          ...reportConfig,
          mode: reportConfig.deliveryMode || 'download',
          recipients: reportConfig.recipients || '',
          emailBody: reportConfig.emailBody || '',
        };

        const response = await fetch(`${API_BASE}/reports/generate`, {
          method: 'POST',
          headers: getAuthHeaders(),
          body: JSON.stringify(payload),
        });

        if (handleApiError(response)) return;

        if (!response.ok) {
          const errorData = await response.json().catch(() => ({}));
          showNotification(errorData.error || 'Failed to generate report', 'error');
          return;
        }

        if ((reportConfig.deliveryMode || 'download') === 'download') {
          const blob = await response.blob();
          const url = window.URL.createObjectURL(blob);
          const a = document.createElement('a');
          a.href = url;
          const timestamp = new Date().toISOString().split('T')[0];
          a.download = `falcon_${reportConfig.type}_report_${timestamp}.${reportConfig.format}`;
          a.click();

          showNotification('Report downloaded successfully', 'success');
        } else {
          const data = await response.json().catch(() => ({}));
          showNotification(data.message || 'Report emailed successfully', 'success');
        }

        setShowReportDialog(false);
      } catch (error) {
        console.error('Error generating report:', error);
        showNotification('Error generating report: ' + error.message, 'error');
      }
    };


  const handleForceRefresh = async () => {
    setIsRefreshing(true);
    await fetchHosts(true);
    setIsRefreshing(false);
  };

  // ============================================================================
  // UTILITY FUNCTIONS
  // ============================================================================
  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50 dark:bg-red-900 dark:text-red-200';
      case 'high': return 'text-orange-600 bg-orange-50 dark:bg-orange-900 dark:text-orange-200';
      case 'medium': return 'text-yellow-600 bg-yellow-50 dark:bg-yellow-900 dark:text-yellow-200';
      case 'low': return 'text-blue-600 bg-blue-50 dark:bg-blue-900 dark:text-blue-200';
      default: return 'text-gray-600 bg-gray-50 dark:bg-gray-700 dark:text-gray-300';
    }
  };

  // ============================================================================
  // MAIN RENDER - LOGIN SCREEN
  // ============================================================================
  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center p-4">
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow-2xl p-8 max-w-md w-full">
          <div className="flex items-center justify-between mb-6">
            <div className="flex items-center">
              <Shield className="w-12 h-12 text-red-600 mr-3" />
              <h1 className="text-3xl font-bold text-gray-800 dark:text-white">Falcon Manager Pro</h1>
            </div>
            <button
              onClick={toggleDarkMode}
              className="p-2 rounded-lg hover:bg-gray-100 dark:hover:bg-gray-700 transition-colors"
              title="Toggle dark mode"
            >
              {darkMode ? <Sun className="w-5 h-5 text-gray-300" /> : <Moon className="w-5 h-5 text-gray-600" />}
            </button>
          </div>
          <p className="text-gray-600 dark:text-gray-400 text-center mb-6">
            Multi-Tenant Security Operations Platform
          </p>
          
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">API Base URL</label>
              <input
                type="text"
                value={credentials.baseUrl}
                onChange={(e) => setCredentials({ ...credentials, baseUrl: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"

              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Client ID</label>
              <input
                type="text"
                value={credentials.clientId}
                onChange={(e) => setCredentials({ ...credentials, clientId: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">Client Secret</label>
              <input
                type="password"
                value={credentials.clientSecret}
                onChange={(e) => setCredentials({ ...credentials, clientSecret: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-2">
                VirusTotal API Key (Optional)
                <span className="text-xs text-gray-500 ml-2">For IOC threat intelligence lookups</span>
              </label>
              <input
                type="password"
                value={credentials.vtApiKey}
                onChange={(e) => setCredentials({ ...credentials, vtApiKey: e.target.value })}
                placeholder="Enter your VirusTotal API key"
                className="w-full px-4 py-2 border border-gray-300 dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>
            <button
              onClick={handleLogin}
              className="w-full bg-red-600 text-white py-3 rounded-lg font-semibold hover:bg-red-700 transition-colors"
            >
              Connect to Falcon
            </button>
          </div>
        </div>
      </div>
    );
  }

  // ============================================================================
  // MAIN DASHBOARD RENDER
  // ============================================================================
  return (
  <div className="min-h-screen bg-gray-50 dark:bg-gray-900">
    {/* HEADER */}
    <header className="bg-white dark:bg-gray-800 shadow-sm border-b border-gray-200 dark:border-gray-700">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Shield className="w-8 h-8 text-red-600" />
              <div>
                <h1 className="text-2xl font-bold text-gray-800 dark:text-white">Falcon Manager Pro</h1>
                {tenantInfo && (
                  <p className="text-sm text-gray-600 dark:text-gray-300">
                    {tenantInfo.name} • {tenantInfo.plan || 'Enterprise'}
                  </p>
                )}
              </div>
              <div className="flex items-center px-3 py-1 bg-green-100 dark:bg-green-900 rounded-full">
                <Activity className="w-4 h-4 text-green-600 dark:text-green-300 mr-2" />
                <span className="text-sm text-green-700 dark:text-green-200">Auto-refresh</span>
              </div>
            </div>
            <div className="flex items-center space-x-3 flex-wrap justify-end">

              {/* Dark Mode Toggle */}
              <button
                onClick={toggleDarkMode}
                className="flex items-center px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600 transition-colors"
                title="Toggle dark mode"
              >
                {darkMode ? <Sun className="w-4 h-4 mr-2" /> : <Moon className="w-4 h-4 mr-2" />}
                {darkMode ? 'Light' : 'Dark'}
              </button>

              <button 
                onClick={() => setShowHelpSidebar(true)} 
                className="flex items-center px-4 py-2 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-lg hover:bg-gray-200 dark:hover:bg-gray-600"
              >
                <HelpCircle className="w-4 h-4 mr-2" />Help
              </button>

            
            <button 
              onClick={() => setShowAdvancedSearchDialog(true)} 
              className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700"
            >
              <Search className="w-4 h-4 mr-2" />Advanced Search
            </button>
            
            <button 
              onClick={() => setShowReportDialog(true)} 
              className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
            >
              <Download className="w-4 h-4 mr-2" />Generate Report
            </button>

            {/* Hash Tools Dropdown */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowHashToolsDropdown(!showHashToolsDropdown);
                  setShowSystemDropdown(false);
                }}
                className="flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700"
              >
                <AlertCircle className="w-4 h-4 mr-2" />
                Hash Tools
                <svg className="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showHashToolsDropdown && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setShowHashToolsDropdown(false)} />
                  <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-gray-800 rounded-lg shadow-lg z-20 border border-gray-200 dark:border-gray-700">
                    <div className="py-1">
                      <button
                        onClick={() => {
                          setShowHashDialog(true);
                          setShowHashToolsDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <AlertCircle className="w-4 h-4 mr-2" />
                        Close by Hash
                      </button>
                      <button
                        onClick={() => {
                          handleHashAnalysis();
                          setShowHashToolsDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <Activity className="w-4 h-4 mr-2" />
                        Hash Analysis
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>

            {/* System Dropdown */}
            <div className="relative">
              <button 
                onClick={() => {
                  setShowSystemDropdown(!showSystemDropdown);
                  setShowHashToolsDropdown(false);
                }}
                className="flex items-center px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
              >
                <Server className="w-4 h-4 mr-2" />
                System
                <svg className="w-4 h-4 ml-1" fill="none" stroke="currentColor" viewBox="0 0 24 24">
                  <path strokeLinecap="round" strokeLinejoin="round" strokeWidth={2} d="M19 9l-7 7-7-7" />
                </svg>
              </button>
              
              {showSystemDropdown && (
                <>
                  <div className="fixed inset-0 z-10" onClick={() => setShowSystemDropdown(false)} />
                  <div className="absolute right-0 mt-2 w-56 bg-white dark:bg-gray-800 rounded-lg shadow-lg z-20 border border-gray-200 dark:border-gray-700">
                    <div className="py-1">
                      <button
                        onClick={() => {
                          handleHealthCheck();
                          setShowSystemDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <Activity className="w-4 h-4 mr-2 text-green-600" />
                        Health Check
                      </button>
                      <button
                        onClick={() => {
                          handleCacheInfo();
                          setShowSystemDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <Server className="w-4 h-4 mr-2 text-gray-600" />
                        Cache Info
                      </button>
                      <button
                        onClick={() => {
                          handleCacheClear();
                          setShowSystemDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <RefreshCw className="w-4 h-4 mr-2 text-yellow-600" />
                        Clear Cache
                      </button>
                      <button
                        onClick={() => {
                          handleDebugHostsTest();
                          setShowSystemDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <Activity className="w-4 h-4 mr-2 text-blue-600" />
                        Debug Tools
                      </button>
                      <button
                        onClick={() => {
                          handleApiIndex();
                          setShowSystemDropdown(false);
                        }}
                        className="w-full text-left px-4 py-2 text-sm text-gray-700 dark:text-gray-300 hover:bg-gray-100 dark:hover:bg-gray-700 flex items-center"
                      >
                        <Book className="w-4 h-4 mr-2 text-indigo-600" />
                        API Documentation
                      </button>
                    </div>
                  </div>
                </>
              )}
            </div>

            <button 
              onClick={handleLogout} 
              className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
            >
              <LogOut className="w-4 h-4 mr-2" />
              Logout
            </button>
          </div>
          </div>
        </div>
      </header>

      {/* STATS CARDS */}
      <div className="px-6 py-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Active Detections ({timeRange >= 24 ? `${timeRange/24}d` : `${timeRange}h`})
                </p>
                <p className="text-3xl font-bold text-gray-800 dark:text-white">
                  {detections.filter((d) => !['false_positive', 'closed', 'ignored'].includes((d.status || '').toLowerCase())).length}
                </p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500" />
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Non-Hash Detections</p>
                <p className="text-3xl font-bold text-gray-800 dark:text-white">{nonHashDetections}</p>
              </div>
              <Server className="w-10 h-10 text-blue-500" />
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Custom IOCs</p>
                <p className="text-3xl font-bold text-gray-800 dark:text-white">{iocs.length}</p>
              </div>
              <AlertCircle className="w-10 h-10 text-orange-500" />
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Managed Hosts</p>
                <p className="text-3xl font-bold text-gray-800 dark:text-white">{hosts.length}</p>
              </div>
              <Server className="w-10 h-10 text-green-500" />
            </div>
          </div>
          
          <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600 dark:text-gray-400">Playbooks</p>
                <p className="text-3xl font-bold text-gray-800 dark:text-white">{playbooks.length}</p>
              </div>
              <Play className="w-10 h-10 text-purple-500" />
            </div>
          </div>
        </div>

        {/* TABS */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow mb-6">
          <div className="border-b border-gray-200 dark:border-gray-700">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'dashboard', name: 'Dashboard', icon: Activity },
                { id: 'detections', name: 'Detections', icon: AlertTriangle },
                { id: 'hosts', name: 'Hosts', icon: Server },
                { id: 'iocs', name: 'IOC Management', icon: AlertCircle },
                { id: 'playbooks', name: 'Playbooks', icon: Play },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id ? 'border-red-600 text-red-600' : 'border-transparent text-gray-500 dark:text-gray-400 hover:text-gray-700 dark:hover:text-gray-300'
                  }`}
                >
                  <tab.icon className="w-5 h-5 mr-2" />
                  {tab.name}
                </button>
              ))}
            </nav>
          </div>

          {/* TAB CONTENT - Components defined below */}
          {activeTab === 'dashboard' && (
            <DashboardTab
              dashboardStats={dashboardStats}
              timeRange={timeRange}
              setTimeRange={setTimeRange}
              detections={detections}
            />
          )}

          {activeTab === 'detections' && (
            <DetectionsTab 
              detections={detections}
              searchQuery={searchQuery}
              setSearchQuery={setSearchQuery}
              selectedSeverity={selectedSeverity}
              setSelectedSeverity={setSelectedSeverity}
              selectedDetections={selectedDetections}
              setSelectedDetections={setSelectedDetections}
              handleBulkUpdate={handleBulkUpdate}
              toggleDetectionSelection={toggleDetectionSelection}
              getSeverityColor={getSeverityColor}
              openCommentDialog={openCommentDialog}
            />
          )}

          {activeTab === 'hosts' && (
            <HostsTab 
              hosts={hosts}
              handleContainHost={handleContainHost}
              handleLiftContainment={handleLiftContainment}
              handleKillProcess={handleKillProcess}
              handleDeleteFile={handleDeleteFile}
              handleRTRFileHash={handleRTRFileHash}
              handleRTRLs={handleRTRLs}
              handleRTRNetstat={handleRTRNetstat}
              handleRTRPs={handleRTRPs}
              handleRTRRegQuery={handleRTRRegQuery}
              handleRTRGetFile={handleRTRGetFile}
              handleRTRMemdump={handleRTRMemdump}
              handleRTRCp={handleRTRCp}
              handleRTRZip={handleRTRZip}
              handleRTRListScripts={handleRTRListScripts}
              handleRTRRunScript={handleRTRRunScript}
              handleRTRPutFile={handleRTRPutFile}
              handleRTRRegDelete={handleRTRRegDelete}
              handleRTRRegSet={handleRTRRegSet}
              handleRTRRestart={handleRTRRestart}
              handleRTRShutdown={handleRTRShutdown}
              isRefreshing={isRefreshing}
              handleForceRefresh={handleForceRefresh}
              platformFilter={platformFilter}
              setPlatformFilter={setPlatformFilter}
            />
          )}

          {activeTab === 'iocs' && (
            <IOCsTab 
              iocs={iocs}
              setShowExclusionDialog={setShowExclusionDialog}
              setShowIOCDialog={setShowIOCDialog}
              getSeverityColor={getSeverityColor}
              handleDeleteIOC={handleDeleteIOC}
              vtData={vtData}
              vtLoading={vtLoading}
              fetchVirusTotalData={fetchVirusTotalData}
            />
          )}

          {activeTab === 'playbooks' && (
            <PlaybooksTab 
              playbooks={playbooks}
              setShowPlaybookDialog={setShowPlaybookDialog}
              onExecuteClick={openExecuteDialog}
              onDeleteClick={handleDeletePlaybook}
              isAuthenticated={isAuthenticated}
              showNotification={showNotification}
              autoTriggerStatus={autoTriggerStatus}
              fetchAutoTriggerStatus={fetchAutoTriggerStatus}
              toggleAutoTrigger={toggleAutoTrigger}
            />
          )}
        </div>
      </div>

      {/* DIALOGS */}
      {showCommentDialog && (
        <CommentDialog 
          commentData={commentData} 
          setCommentData={setCommentData} 
          onConfirm={handleDetectionAction} 
          onClose={() => setShowCommentDialog(false)} 
        />
      )}
      
      {showIOCDialog && (
        <IOCDialog 
          onClose={() => setShowIOCDialog(false)} 
          onCreate={handleCreateIOC} 
        />
      )}
      
      {showPlaybookDialog && (
        <PlaybookDialog 
          onClose={() => setShowPlaybookDialog(false)} 
          onCreate={handleCreatePlaybook} 
        />
      )}
      
      {showHashDialog && (
        <CloseByHashDialog 
          onClose={() => setShowHashDialog(false)} 
          onSubmit={handleCloseByHash}
          initialHash={preselectedHash}
        />
      )}
      
      {showHashAnalysisDialog && hashAnalysis && (
        <HashAnalysisDialog 
          data={hashAnalysis} 
          onClose={() => setShowHashAnalysisDialog(false)} 
          onCloseHash={(hash) => {
            setPreselectedHash(hash);
            setShowHashAnalysisDialog(false);
            setShowHashDialog(true);
          }} 
          onCreateExclusion={(hash) => {
            setPreselectedHash(hash);
            setShowHashAnalysisDialog(false);
            setShowExclusionDialog(true);
          }} 
        />
      )}
      
      {showAdvancedSearchDialog && (
        <AdvancedSearchDialog 
          onClose={() => setShowAdvancedSearchDialog(false)} 
          onSearch={handleAdvancedSearch} 
        />
      )}
      
      {showExclusionDialog && (
        <IOCExclusionDialog 
          onClose={() => setShowExclusionDialog(false)} 
          onCreate={handleCreateExclusion}
          initialHash={preselectedHash}
        />
      )}
      
      {showReportDialog && (
        <ReportDialog 
          onClose={() => setShowReportDialog(false)} 
          onGenerate={handleGenerateReport} 
          detections={detections} 
          hosts={hosts} 
          iocs={iocs} 
          dashboardStats={dashboardStats} 
        />
      )}
      
      {showHelpSidebar && (
        <HelpSidebar
          activeTab={activeTab}
          onClose={() => setShowHelpSidebar(false)}
          onChangeTab={(tab) => setActiveTab(tab)}   // ⬅️ THIS is what makes the help tabs switch views
        />
      )}

      {showExecuteDialog && executePlaybook && (
        <PlaybookExecuteDialog
          playbook={executePlaybook}
          detections={detections}
          hosts={hosts}
          onClose={() => setShowExecuteDialog(false)}
          onRun={async (targetType, targetId) => {
            await handleExecutePlaybook(executePlaybook.id, targetType, targetId);
            setShowExecuteDialog(false);
          }}
        />
      )}

      {showRTROutputDialog && rtrOutput && (
        <RTROutputDialog
          title={rtrOutput.title}
          data={rtrOutput.data}
          onClose={() => setShowRTROutputDialog(false)}
        />
      )}

      {/* NOTIFICATIONS */}
      {notification && (
        <div className={`fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg ${
          notification.type === 'success' ? 'bg-green-600' : 'bg-red-600'
        } text-white z-50`}>
          {notification.message}
        </div>
      )}
    </div>
  );
};

// ============================================================================
// TAB COMPONENT DECLARATIONS
// ============================================================================

// Dashboard Tab Component
const DashboardTab = ({ dashboardStats, timeRange, setTimeRange, detections }) => {
  if (!dashboardStats) {
    return (
      <div className="p-6">
        <div className="flex items-center justify-center h-64">
          <div className="text-center">
            <Activity className="w-12 h-12 text-gray-400 mx-auto mb-4 animate-pulse" />
            <p className="text-gray-600 dark:text-gray-400">Loading dashboard data...</p>
          </div>
        </div>
      </div>
    );
  }

  const hours = parseInt(timeRange);
  const timeRangeLabel = hours >= 24 
    ? `Last ${hours / 24} Day${hours > 24 ? 's' : ''}` 
    : `Last ${hours} Hour${hours > 1 ? 's' : ''}`;

  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-6">
        <h2 className="text-2xl font-bold text-gray-800 dark:text-white">Security Analytics Dashboard</h2>
        <div className="flex items-center space-x-3 px-4 py-2 bg-white dark:bg-gray-800 border border-gray-300 dark:border-gray-600 rounded-lg shadow-sm">
          <Activity className="w-4 h-4 text-blue-600" />
          <select
            value={timeRange}
            onChange={(e) => setTimeRange(e.target.value)}
            className="text-sm font-medium text-gray-700 dark:text-gray-300 bg-transparent border-none focus:ring-0 cursor-pointer"
          >
            <option value="1">Last 1 Hour</option>
            <option value="6">Last 6 Hours</option>
            <option value="12">Last 12 Hours</option>
            <option value="24">Last 24 Hours</option>
            <option value="48">Last 2 Days</option>
            <option value="168">Last 7 Days</option>
            <option value="720">Last 30 Days</option>
          </select>
        </div>
      </div>

      {/* SEVERITY CARDS */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-4 mb-6">
        <div className="bg-gradient-to-br from-red-50 to-red-100 dark:from-red-900 dark:to-red-800 rounded-lg shadow p-6 border border-red-200 dark:border-red-700">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-red-900 dark:text-red-100">Critical</h3>
            <AlertTriangle className="w-6 h-6 text-red-600 dark:text-red-300" />
          </div>
          <p className="text-3xl font-bold text-red-700 dark:text-red-200">{dashboardStats.severityCounts.critical || 0}</p>
          <p className="text-xs text-red-600 dark:text-red-300 mt-1">Immediate attention</p>
        </div>
        
        <div className="bg-gradient-to-br from-orange-50 to-orange-100 dark:from-orange-900 dark:to-orange-800 rounded-lg shadow p-6 border border-orange-200 dark:border-orange-700">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-orange-900 dark:text-orange-100">High</h3>
            <AlertCircle className="w-6 h-6 text-orange-600 dark:text-orange-300" />
          </div>
          <p className="text-3xl font-bold text-orange-700 dark:text-orange-200">{dashboardStats.severityCounts.high || 0}</p>
          <p className="text-xs text-orange-600 dark:text-orange-300 mt-1">High priority</p>
        </div>
        
        <div className="bg-gradient-to-br from-yellow-50 to-yellow-100 dark:from-yellow-900 dark:to-yellow-800 rounded-lg shadow p-6 border border-yellow-200 dark:border-yellow-700">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-yellow-900 dark:text-yellow-100">Medium</h3>
            <Activity className="w-6 h-6 text-yellow-600 dark:text-yellow-300" />
          </div>
          <p className="text-3xl font-bold text-yellow-700 dark:text-yellow-200">{dashboardStats.severityCounts.medium || 0}</p>
          <p className="text-xs text-yellow-600 dark:text-yellow-300 mt-1">Monitor closely</p>
        </div>
        
        <div className="bg-gradient-to-br from-blue-50 to-blue-100 dark:from-blue-900 dark:to-blue-800 rounded-lg shadow p-6 border border-blue-200 dark:border-blue-700">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-blue-900 dark:text-blue-100">Low</h3>
            <Shield className="w-6 h-6 text-blue-600 dark:text-blue-300" />
          </div>
          <p className="text-3xl font-bold text-blue-700 dark:text-blue-200">{dashboardStats.severityCounts.low || 0}</p>
          <p className="text-xs text-blue-600 dark:text-blue-300 mt-1">Low risk</p>
        </div>
        
        <div className="bg-gradient-to-br from-purple-50 to-purple-100 dark:from-purple-900 dark:to-purple-800 rounded-lg shadow p-6 border border-purple-200 dark:border-purple-700">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-purple-900 dark:text-purple-100">Info</h3>
            <HelpCircle className="w-6 h-6 text-purple-600 dark:text-purple-300" />
          </div>
          <p className="text-3xl font-bold text-purple-700 dark:text-purple-200">{dashboardStats.severityCounts.informational || 0}</p>
          <p className="text-xs text-purple-600 dark:text-purple-300 mt-1">Informational</p>
        </div>
        
        <div className="bg-gradient-to-br from-gray-50 to-gray-100 dark:from-gray-800 dark:to-gray-700 rounded-lg shadow p-6 border border-gray-200 dark:border-gray-600">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-sm font-semibold text-gray-900 dark:text-gray-100">Unknown</h3>
            <HelpCircle className="w-6 h-6 text-gray-600 dark:text-gray-300" />
          </div>
          <p className="text-3xl font-bold text-gray-700 dark:text-gray-200">{dashboardStats.severityCounts.unknown || 0}</p>
          <p className="text-xs text-gray-600 dark:text-gray-300 mt-1">Not classified</p>
        </div>
      </div>

      {/* TIMELINE AND STATUS CHARTS */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
         {/* TIMELINE CHART */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 dark:text-white mb-4">
            Detection Timeline ({timeRangeLabel})
          </h3>
          <div className="h-80 flex items-end space-x-1 overflow-x-auto pb-16 px-2">
            {dashboardStats.timelineData.map((bucket, idx) => {
              const maxHeight = Math.max(...dashboardStats.timelineData.map(b => b.total));
              const height = maxHeight > 0 ? (bucket.total / maxHeight) * 100 : 0;
              
              return (
                <div 
                  key={idx} 
                  className="flex-shrink-0 flex flex-col items-center" 
                  style={{ width: hours > 48 ? '32px' : '48px' }}
                >
                  <div className="w-full flex flex-col justify-end" style={{ height: '200px' }}>
                    {bucket.critical > 0 && (
                      <div 
                        className="w-full bg-red-500 dark:bg-red-400 hover:bg-red-600 dark:hover:bg-red-500 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.critical / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - Critical: ${bucket.critical}`} 
                      />
                    )}
                    {bucket.high > 0 && (
                      <div 
                        className="w-full bg-orange-500 dark:bg-orange-400 hover:bg-orange-600 dark:hover:bg-orange-500 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.high / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - High: ${bucket.high}`} 
                      />
                    )}
                    {bucket.medium > 0 && (
                      <div 
                        className="w-full bg-yellow-500 dark:bg-yellow-400 hover:bg-yellow-600 dark:hover:bg-yellow-500 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.medium / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - Medium: ${bucket.medium}`} 
                      />
                    )}
                    {bucket.low > 0 && (
                      <div 
                        className="w-full bg-blue-500 dark:bg-blue-400 hover:bg-blue-600 dark:hover:bg-blue-500 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.low / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - Low: ${bucket.low}`} 
                      />
                    )}
                    {bucket.informational > 0 && (
                      <div 
                        className="w-full bg-purple-500 dark:bg-purple-400 hover:bg-purple-600 dark:hover:bg-purple-500 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.informational / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - Info: ${bucket.informational}`} 
                      />
                    )}
                    {bucket.unknown > 0 && (
                      <div 
                        className="w-full bg-gray-500 dark:bg-gray-300 hover:bg-gray-600 dark:hover:bg-gray-400 transition-colors cursor-pointer" 
                        style={{ height: `${(bucket.unknown / bucket.total) * height * 2}px` }} 
                        title={`${bucket.label} - Unknown: ${bucket.unknown}`} 
                      />
                    )}
                  </div>
                  
                  {/* VISIBLE LABELS - Improved for dark mode */}
                  <div className="relative mt-2" style={{ height: '45px', width: '100%' }}>
                    <span 
                      className="absolute text-gray-800 dark:text-white font-medium whitespace-nowrap"
                      style={{ 
                        fontSize: '10px',
                        transform: 'rotate(-45deg)',
                        transformOrigin: 'left top',
                        left: '50%',
                        top: '8px'
                      }}
                    >
                      {bucket.label}
                    </span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex justify-center space-x-4 mt-2 text-xs flex-wrap text-gray-700 dark:text-gray-200">
            <div className="flex items-center"><div className="w-3 h-3 bg-red-500 dark:bg-red-400 rounded mr-1"></div> Critical</div>
            <div className="flex items-center"><div className="w-3 h-3 bg-orange-500 dark:bg-orange-400 rounded mr-1"></div> High</div>
            <div className="flex items-center"><div className="w-3 h-3 bg-yellow-500 dark:bg-yellow-400 rounded mr-1"></div> Medium</div>
            <div className="flex items-center"><div className="w-3 h-3 bg-blue-500 dark:bg-blue-400 rounded mr-1"></div> Low</div>
            <div className="flex items-center"><div className="w-3 h-3 bg-purple-500 dark:bg-purple-400 rounded mr-1"></div> Info</div>
            <div className="flex items-center"><div className="w-3 h-3 bg-gray-500 dark:bg-gray-300 rounded mr-1"></div> Unknown</div>
          </div>
          <p className="text-xs text-gray-500 dark:text-gray-400 text-center mt-2">
            {dashboardStats.bucketSizeHours === 1 ? 'Hourly' : 
            dashboardStats.bucketSizeHours === 4 ? '4-Hour' : 
            'Daily'} buckets
          </p>
        </div>

        {/* STATUS BREAKDOWN */}
        <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
          <h3 className="text-lg font-bold text-gray-800 dark:text-white mb-4">Detection Status Breakdown</h3>
          <div className="space-y-3">
            {Object.entries(dashboardStats.statusCounts).map(([status, count]) => {
              const percentage = dashboardStats.totalDetections > 0 
                ? ((count / dashboardStats.totalDetections) * 100).toFixed(1) 
                : 0;
              const statusColors = {
                new: 'bg-blue-500',
                in_progress: 'bg-yellow-500',
                true_positive: 'bg-red-500',
                false_positive: 'bg-gray-500',
                closed: 'bg-green-500',
                ignored: 'bg-gray-400'
              };
              return (
                <div key={status} className="space-y-1">
                  <div className="flex justify-between text-sm">
                    <span className="font-medium text-gray-700 dark:text-gray-300 capitalize">{status.replace('_', ' ')}</span>
                    <span className="text-gray-600 dark:text-gray-400">{count} ({percentage}%)</span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div 
                      className={`${statusColors[status]} h-2 rounded-full transition-all duration-500`} 
                      style={{ width: `${percentage}%` }} 
                    />
                  </div>
                </div>
              );
            })}
          </div>
        </div>
      </div>

      {/* SUMMARY STATISTICS */}
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow p-6">
        <h3 className="text-lg font-bold text-gray-800 dark:text-white mb-4">Summary Statistics</h3>
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
            <p className="text-2xl font-bold text-gray-800 dark:text-white">
              {dashboardStats.totalDetections}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Total Detections</p>
          </div>

          <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
            <p className="text-2xl font-bold text-gray-800 dark:text-white">
              {(dashboardStats.severityCounts.critical || 0) +
                (dashboardStats.severityCounts.high || 0)}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">High Priority</p>
          </div>

          <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
            <p className="text-2xl font-bold text-gray-800 dark:text-white">
              {(
                ((dashboardStats.statusCounts.closed || 0) +
                  (dashboardStats.statusCounts.false_positive || 0)) /
                Math.max(dashboardStats.totalDetections || 1, 1) *
                100
              ).toFixed(1)}
              %
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Resolution Rate</p>
          </div>

          <div className="text-center p-4 bg-gray-50 dark:bg-gray-900 rounded-lg">
            <p className="text-2xl font-bold text-gray-800 dark:text-white">
              {dashboardStats.statusCounts.new || 0}
            </p>
            <p className="text-sm text-gray-600 dark:text-gray-400">Pending Review</p>
          </div>
        </div>
      </div>

      {/* MITRE ATT&CK Matrix */}
      <div className="mt-6">
        <MitreAttackMatrix detections={detections} />
      </div>
    </div>
  );
};

const DetectionsTab = ({ 
  detections, searchQuery, setSearchQuery, selectedSeverity, setSelectedSeverity, 
  selectedDetections, setSelectedDetections, handleBulkUpdate, toggleDetectionSelection, 
  getSeverityColor, openCommentDialog 
}) => {
  const filteredDetections = detections
    .filter(d => {
      if (selectedSeverity === 'all') return true;
      return (d.severity || '').toLowerCase() === selectedSeverity.toLowerCase();
    })
    .filter((d) => (d.name || '').toLowerCase().includes(searchQuery.toLowerCase()));

  return (
    <div className="p-6">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center space-x-4 flex-1">
          <input
            type="text"
            placeholder="Search detections..."
            value={searchQuery}
            onChange={(e) => setSearchQuery(e.target.value)}
            className="flex-1 px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          />
          <select
            value={selectedSeverity}
            onChange={(e) => setSelectedSeverity(e.target.value)}
            className="px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="all">All Severities</option>
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
            <option value="informational">Informational</option>
            <option value="unknown">Unknown</option>
          </select>
        </div>
        {selectedDetections.length > 0 && (
          <div className="flex space-x-2 ml-4">
            <button 
              onClick={() => handleBulkUpdate('true_positive')} 
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
            >
              Bulk Resolve ({selectedDetections.length})
            </button>
            <button 
              onClick={() => handleBulkUpdate('false_positive')} 
              className="px-4 py-2 bg-gray-600 text-white rounded-lg hover:bg-gray-700"
            >
              Bulk Close ({selectedDetections.length})
            </button>
          </div>
        )}
      </div>
      
      <div className="flex items-center mb-3 pb-2 border-b dark:border-gray-700">
        <input
          type="checkbox"
          checked={selectedDetections.length === filteredDetections.length && filteredDetections.length > 0}
          onChange={(e) => {
            if (e.target.checked) {
              setSelectedDetections(filteredDetections.map(d => d.id));
            } else {
              setSelectedDetections([]);
            }
          }}
          className="mr-3"
        />
        <span className="text-sm font-medium text-gray-700 dark:text-gray-300">
          Select All ({filteredDetections.length} detections)
        </span>
      </div>
      
     <div className="space-y-4">
  {filteredDetections.map((detection) => {
    const { tactics, techniques } = mapToMitreAttack(detection);

    return (
      <div
        key={detection.id}
        className="border dark:border-gray-700 rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-gray-800"
      >
        <div className="flex items-start">
          <input
            type="checkbox"
            checked={selectedDetections.includes(detection.id)}
            onChange={() => toggleDetectionSelection(detection.id)}
            className="mt-1 mr-4"
          />
          <div className="flex-1">
            <div className="flex items-center space-x-3 mb-2 flex-wrap gap-2">
              <span
                className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getSeverityColor(
                  (detection.severity || 'unknown').toLowerCase()
                )}`}
              >
                {detection.severity || 'unknown'}
              </span>
              <span className="text-sm text-gray-600 dark:text-gray-400 capitalize">
                {detection.status || 'new'}
              </span>

              {tactics.map((tacticKey) => (
                <MitreTacticBadge key={tacticKey} tacticKey={tacticKey} size="sm" />
              ))}

              <span className="text-sm text-gray-500 dark:text-gray-400">
                Assigned: {detection.assigned_to || 'Unassigned'}
              </span>
            </div>

            <h3 className="text-lg font-semibold text-gray-800 dark:text-white mb-2">
              {detection.name || 'Unknown'}
            </h3>

            {techniques.length > 0 && (
              <div className="flex flex-wrap gap-2 mb-3">
                {techniques.map((techniqueId) => (
                  <MitreTechniqueBadge key={techniqueId} techniqueId={techniqueId} size="sm" />
                ))}
              </div>
            )}

            <div className="flex items-center space-x-4 text-sm text-gray-600 dark:text-gray-400">
              <span>
                Host:{' '}
                <span className="font-medium">{detection.host || 'Unknown'}</span>
              </span>
              <span>Behavior: {detection.behavior || 'Unknown'}</span>
              <span>
                {detection.timestamp ? new Date(detection.timestamp).toLocaleString() : 'N/A'}
              </span>
            </div>
          </div>
          <div className="flex space-x-2">
            <button
              onClick={() => openCommentDialog(detection.id, 'resolve')}
              className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm"
            >
              Resolve
            </button>
            <button
              onClick={() => openCommentDialog(detection.id, 'close_fp')}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
            >
              Close (FP)
            </button>
            <button
              onClick={() => openCommentDialog(detection.id, 'ignore')}
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-700 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600 text-sm"
            >
              Ignore
            </button>
          </div>
        </div>
      </div>
    );
  })}
</div>
    </div>
  );
};

const HostsTab = ({
  hosts, handleContainHost, handleLiftContainment, handleKillProcess, handleDeleteFile,
  handleRTRFileHash, handleRTRLs, handleRTRNetstat, handleRTRPs, handleRTRRegQuery,
  handleRTRGetFile, handleRTRMemdump, handleRTRCp, handleRTRZip, handleRTRListScripts,
  handleRTRRunScript, handleRTRPutFile, handleRTRRegDelete, handleRTRRegSet,
  handleRTRRestart, handleRTRShutdown, isRefreshing, handleForceRefresh,
  platformFilter, setPlatformFilter
}) => {
  const [searchQuery, setSearchQuery] = useState('');
  
  const filteredHosts = hosts.filter(host => {
    const hostname = (host.hostname || '').toLowerCase();
    const ip = host.ip || '';
    const matchesSearch = hostname.includes(searchQuery.toLowerCase()) || ip.includes(searchQuery);
    const matchesPlatform = platformFilter === 'all' || (host.os || '').toLowerCase().includes(platformFilter.toLowerCase());
    return matchesSearch && matchesPlatform;
  });
  
  return (
    <div className="p-6">
      <div className="flex justify-between items-center mb-4">
        <div>
          <h2 className="text-xl font-bold text-gray-800 dark:text-white">Managed Hosts</h2>
          <p className="text-sm text-gray-600 dark:text-gray-400">Total in system: {hosts.length.toLocaleString()} hosts</p>
        </div>
        <div className="flex space-x-2">
          <button 
            onClick={handleForceRefresh}
            disabled={isRefreshing}
            className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700 disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 mr-2 ${isRefreshing ? 'animate-spin' : ''}`} />
            {isRefreshing ? 'Refreshing...' : 'Force Refresh from API'}
          </button>
        </div>
      </div>
      
      <div className="flex space-x-2 mb-4">
        <input
          type="text"
          placeholder="Search hostname or IP..."
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          className="flex-1 px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        />
        <select
          value={platformFilter}
          onChange={(e) => setPlatformFilter(e.target.value)}
          className="px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        >
          <option value="all">All Platforms</option>
          <option value="windows">Windows</option>
          <option value="linux">Linux</option>
          <option value="mac">Mac</option>
        </select>
      </div>
      
      {filteredHosts.length === 0 ? (
        <div className="text-center py-12 bg-gray-50 dark:bg-gray-900 rounded-lg">
          <Server className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-400">No hosts found matching your filters</p>
          {hosts.length === 0 && (
            <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">Click "Force Refresh from API" to load hosts</p>
          )}
        </div>
      ) : (
        <>
          <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-3 mb-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center space-x-4">
                <div>
                  <span className="text-sm text-blue-800 dark:text-blue-200 font-semibold">Displaying: </span>
                  <span className="text-sm text-blue-900 dark:text-blue-100">{filteredHosts.length.toLocaleString()} of {hosts.length.toLocaleString()} hosts</span>
                </div>
                {filteredHosts.length !== hosts.length && (
                  <div>
                    <span className="text-sm text-blue-700 dark:text-blue-300">({(hosts.length - filteredHosts.length).toLocaleString()} filtered out)</span>
                  </div>
                )}
              </div>
            </div>
          </div>
          
          <div className="space-y-4">
            {filteredHosts.slice(0, 100).map((host) => (
              <div key={host.id} className="border dark:border-gray-700 rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-gray-800">
                <div className="flex justify-between">
                  <div>
                    <h3 className="font-semibold text-lg text-gray-800 dark:text-white">{host.hostname}</h3>
                    <p className="text-sm text-gray-600 dark:text-gray-400">IP: {host.ip}</p>
                    <p className="text-sm text-gray-600 dark:text-gray-400">OS: {host.os}</p>
                    {host.agent_version && <p className="text-sm text-gray-600 dark:text-gray-400">Agent: {host.agent_version}</p>}
                  </div>
                  <div className="flex items-center space-x-2">
                    {host.contained && (
                      <span className="px-3 py-1 rounded-full text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200">
                        Contained
                      </span>
                    )}
                    <span className={`px-3 py-1 rounded-full text-xs ${
                      host.status === 'online' ? 'bg-green-100 dark:bg-green-900 text-green-800 dark:text-green-200' : 'bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200'
                    }`}>
                      {host.status}
                    </span>
                  </div>
                </div>

                <div className="flex flex-col space-y-2 mt-4">
                  {/* Tier 0: Core actions */}
                  <div className="flex flex-wrap gap-2">
                    <button 
                      onClick={() => handleContainHost(host.id)} 
                      className="px-3 py-2 text-xs bg-purple-600 text-white rounded-lg hover:bg-purple-700"
                    >
                      Network Contain
                    </button>
                    <button 
                      onClick={() => handleLiftContainment(host.id)} 
                      className="px-3 py-2 text-xs bg-green-600 text-white rounded-lg hover:bg-green-700"
                    >
                      Lift Containment
                    </button>
                    <button 
                      onClick={() => handleKillProcess(host.id)} 
                      className="px-3 py-2 text-xs bg-red-600 text-white rounded-lg hover:bg-red-700"
                    >
                      Kill Process (RTR)
                    </button>
                    <button 
                      onClick={() => handleDeleteFile(host.id)} 
                      className="px-3 py-2 text-xs bg-orange-600 text-white rounded-lg hover:bg-orange-700"
                    >
                      Delete File (RTR)
                    </button>
                  </div>

                  {/* Tier 1 – Read-only */}
                  <div className="flex flex-wrap gap-2 items-center">
                    <span className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 mr-1 mt-1">Tier 1</span>
                    <button onClick={() => handleRTRFileHash(host.id)} className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-200 dark:hover:bg-gray-600">filehash</button>
                    <button onClick={() => handleRTRLs(host.id)} className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-200 dark:hover:bg-gray-600">ls</button>
                    <button onClick={() => handleRTRPs(host.id)} className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-200 dark:hover:bg-gray-600">ps</button>
                    <button onClick={() => handleRTRNetstat(host.id)} className="px-3 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded hover:bg-gray-200 dark:hover:bg-gray-600">netstat</button>
                  </div>

                  {/* Tier 2 – Active responder */}
                  <div className="flex flex-wrap gap-2 items-center">
                    <span className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 mr-1 mt-1">Tier 2</span>
                    <button onClick={() => handleRTRRegQuery(host.id)} className="px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded hover:bg-blue-200 dark:hover:bg-blue-800">reg-query</button>
                    <button onClick={() => handleRTRGetFile(host.id)} className="px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded hover:bg-blue-200 dark:hover:bg-blue-800">get-file</button>
                    <button onClick={() => handleRTRMemdump(host.id)} className="px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded hover:bg-blue-200 dark:hover:bg-blue-800">memdump</button>
                    <button onClick={() => handleRTRCp(host.id)} className="px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded hover:bg-blue-200 dark:hover:bg-blue-800">cp</button>
                    <button onClick={() => handleRTRZip(host.id)} className="px-3 py-1 text-xs bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded hover:bg-blue-200 dark:hover:bg-blue-800">zip</button>
                  </div>

                  {/* Tier 3 – Admin */}
                  <div className="flex flex-wrap gap-2 items-center">
                    <span className="text-[10px] uppercase tracking-wide text-gray-500 dark:text-gray-400 mr-1 mt-1">Tier 3</span>
                    <button onClick={handleRTRListScripts} className="px-3 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded hover:bg-purple-200 dark:hover:bg-purple-800">list scripts</button>
                    <button onClick={() => handleRTRRunScript(host.id)} className="px-3 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded hover:bg-purple-200 dark:hover:bg-purple-800">runscript</button>
                    <button onClick={() => handleRTRPutFile(host.id)} className="px-3 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded hover:bg-purple-200 dark:hover:bg-purple-800">put-file</button>
                    <button onClick={() => handleRTRRegDelete(host.id)} className="px-3 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded hover:bg-purple-200 dark:hover:bg-purple-800">reg-delete</button>
                    <button onClick={() => handleRTRRegSet(host.id)} className="px-3 py-1 text-xs bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded hover:bg-purple-200 dark:hover:bg-purple-800">reg-set</button>
                    <button onClick={() => handleRTRRestart(host.id)} className="px-3 py-1 text-xs bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded hover:bg-red-200 dark:hover:bg-red-800">restart</button>
                    <button onClick={() => handleRTRShutdown(host.id)} className="px-3 py-1 text-xs bg-red-100 dark:bg-red-900 text-red-800 dark:text-red-200 rounded hover:bg-red-200 dark:hover:bg-red-800">shutdown</button>
                  </div>
                </div>
              </div>
            ))}
          </div>
          
          {filteredHosts.length > 100 && (
            <div className="mt-6 p-4 bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg">
              <p className="text-sm text-yellow-800 dark:text-yellow-200">
                <strong>Note:</strong> Showing first 100 of {filteredHosts.length.toLocaleString()} filtered hosts for performance. 
                Use search to narrow down results.
              </p>
            </div>
          )}
        </>
      )}
    </div>
  );
};

const IOCsTab = ({ 
  iocs, setShowExclusionDialog, setShowIOCDialog, getSeverityColor, handleDeleteIOC, 
  vtData, vtLoading, fetchVirusTotalData 
}) => (
  <div className="p-6">
    <div className="flex justify-between mb-4">
      <h2 className="text-xl font-bold text-gray-800 dark:text-white">Custom IOC Management</h2>
      <div className="flex space-x-2">
        <button 
          onClick={() => setShowExclusionDialog(true)} 
          className="flex items-center px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700"
        >
          <Plus className="w-4 h-4 mr-2" />Add Exclusion
        </button>
        <button 
          onClick={() => setShowIOCDialog(true)} 
          className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700"
        >
          <Plus className="w-4 h-4 mr-2" />Add IOC
        </button>
      </div>
    </div>
    
    {iocs.length === 0 ? (
      <div className="text-center py-12 bg-gray-50 dark:bg-gray-900 rounded-lg">
        <AlertCircle className="w-12 h-12 text-gray-400 mx-auto mb-4" />
        <p className="text-gray-600 dark:text-gray-400">No custom IOCs found</p>
        <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">Create your first IOC to start monitoring custom indicators</p>
      </div>
    ) : (
      <div className="space-y-4">
        {iocs.map((ioc) => {
          const isHash = ['md5', 'sha1', 'sha256'].includes(ioc.type);
          const vtInfo = vtData[ioc.value];
          const isVTLoading = vtLoading[ioc.value];
          
          return (
            <div key={ioc.id} className="border dark:border-gray-700 rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-gray-800">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <div className="flex items-center space-x-3 mb-2">
                    <span className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getSeverityColor((ioc.severity || 'unknown').toLowerCase())}`}>
                      {ioc.severity}
                    </span>
                    <span className="px-3 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-xs font-semibold uppercase">
                      {ioc.type}
                    </span>
                    <span className="px-3 py-1 bg-purple-100 dark:bg-purple-900 text-purple-800 dark:text-purple-200 rounded-full text-xs font-semibold">
                      {ioc.policy || 'detect'}
                    </span>
                  </div>
                  <div className="font-mono text-sm bg-gray-50 dark:bg-gray-900 px-3 py-2 rounded mb-2 break-all text-gray-800 dark:text-gray-200">{ioc.value}</div>
                  <p className="text-sm text-gray-600 dark:text-gray-400">{ioc.description || 'No description provided'}</p>
                  {ioc.tags && ioc.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1 mt-2">
                      {ioc.tags.map((tag, idx) => (
                        <span key={idx} className="px-2 py-1 bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded text-xs">{tag}</span>
                      ))}
                    </div>
                  )}
                  
                  {isHash && (
                    <div className="mt-3">
                      {!vtInfo && !isVTLoading && (
                        <button
                          onClick={() => fetchVirusTotalData(ioc.value)}
                          className="px-3 py-1 bg-blue-600 text-white rounded text-sm hover:bg-blue-700 flex items-center"
                        >
                          <Search className="w-3 h-3 mr-1" />
                          Check VirusTotal
                        </button>
                      )}
                      
                      {isVTLoading && (
                        <div className="flex items-center text-sm text-gray-600 dark:text-gray-400">
                          <RefreshCw className="w-4 h-4 mr-2 animate-spin" />
                          Checking VirusTotal...
                        </div>
                      )}
                      
                      {vtInfo && !vtInfo.error && (
                        <div className="bg-blue-50 dark:bg-blue-900 border border-blue-200 dark:border-blue-700 rounded-lg p-3 mt-2">
                          <div className="flex items-center justify-between mb-2">
                            <span className="text-sm font-semibold text-blue-900 dark:text-blue-100">VirusTotal Analysis</span>
                            <a
                              href={`https://www.virustotal.com/gui/file/${ioc.value}`}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-xs text-blue-600 dark:text-blue-300 hover:text-blue-800 dark:hover:text-blue-100 underline"
                            >
                              View Full Report →
                            </a>
                          </div>
                          <div className="grid grid-cols-2 gap-2 text-sm">
                            <div>
                              <span className="text-gray-600 dark:text-gray-300">Detection Ratio:</span>
                              <span className={`ml-2 font-bold ${vtInfo.malicious > 0 ? 'text-red-600 dark:text-red-400' : 'text-green-600 dark:text-green-400'}`}>
                                {vtInfo.malicious}/{vtInfo.total}
                              </span>
                            </div>
                            <div>
                              <span className="text-gray-600 dark:text-gray-300">Verdict:</span>
                              <span className={`ml-2 font-bold ${
                                vtInfo.malicious > 10 ? 'text-red-600 dark:text-red-400' : 
                                vtInfo.malicious > 3 ? 'text-orange-600 dark:text-orange-400' : 
                                vtInfo.malicious > 0 ? 'text-yellow-600 dark:text-yellow-400' : 
                                'text-green-600 dark:text-green-400'
                              }`}>
                                {vtInfo.malicious > 10 ? 'Malicious' : 
                                 vtInfo.malicious > 3 ? 'Suspicious' : 
                                 vtInfo.malicious > 0 ? 'Possibly Malicious' : 
                                 'Clean'}
                              </span>
                            </div>
                          </div>
                          {vtInfo.names && vtInfo.names.length > 0 && (
                            <div className="mt-2">
                              <span className="text-xs text-gray-600 dark:text-gray-400">File Names:</span>
                              <div className="text-xs text-gray-700 dark:text-gray-300 mt-1 max-h-20 overflow-y-auto">
                                {vtInfo.names.slice(0, 5).join(', ')}
                                {vtInfo.names.length > 5 && ` (+${vtInfo.names.length - 5} more)`}
                              </div>
                            </div>
                          )}
                          {vtInfo.first_seen && (
                            <div className="mt-2 text-xs text-gray-600 dark:text-gray-400">
                              First Seen: {new Date(vtInfo.first_seen * 1000).toLocaleDateString()}
                            </div>
                          )}
                        </div>
                      )}
                      
                      {vtInfo && vtInfo.error && (
                        <div className="bg-yellow-50 dark:bg-yellow-900 border border-yellow-200 dark:border-yellow-700 rounded-lg p-2 text-sm text-yellow-800 dark:text-yellow-200 mt-2">
                          {vtInfo.error}
                        </div>
                      )}
                    </div>
                  )}
                </div>
                <button 
                  onClick={() => handleDeleteIOC(ioc.id)} 
                  className="ml-4 px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 text-sm flex items-center"
                >
                  <Trash2 className="w-4 h-4 mr-1" />
                  Delete
                </button>
              </div>
            </div>
          );
        })}
      </div>
    )}
  </div>
);

const PlaybooksTab = ({ 
  playbooks, setShowPlaybookDialog, onExecuteClick, onDeleteClick, 
  isAuthenticated, showNotification, autoTriggerStatus, fetchAutoTriggerStatus, toggleAutoTrigger
}) => {
  useEffect(() => {
    if (isAuthenticated && fetchAutoTriggerStatus) {
      fetchAutoTriggerStatus();
      const interval = setInterval(fetchAutoTriggerStatus, 30000);
      return () => clearInterval(interval);
    }
  }, [isAuthenticated, fetchAutoTriggerStatus]);

  return (
    <div className="p-6">
      <div className="flex justify-between mb-4">
        <h2 className="text-xl font-bold text-gray-800 dark:text-white">Automated Response Playbooks</h2>
        <button 
          onClick={() => setShowPlaybookDialog(true)} 
          className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700"
        >
          <Plus className="w-4 h-4 mr-2" />Create Playbook
        </button>
      </div>

      {autoTriggerStatus && (
        <div className="mb-6 bg-gradient-to-r from-purple-50 to-blue-50 dark:from-purple-900 dark:to-blue-900 border border-purple-200 dark:border-purple-700 rounded-lg p-4">
          <div className="flex items-center justify-between">
            <div className="flex-1">
              <h3 className="font-semibold text-gray-800 dark:text-white mb-1 flex items-center">
                <Activity className="w-5 h-5 mr-2 text-purple-600 dark:text-purple-400" />
                Automatic Playbook Triggers
              </h3>
              <div className="text-sm text-gray-600 dark:text-gray-300 space-y-1">
                <div className="flex items-center space-x-4 flex-wrap">
                  <span>Check interval: <strong>{autoTriggerStatus.interval_seconds}s</strong></span>
                  <span>Active playbooks: <strong>{autoTriggerStatus.active_playbooks}</strong></span>
                  <span>Detections processed: <strong>{autoTriggerStatus.processed_count}</strong></span>
                </div>
                {autoTriggerStatus.last_check && (
                  <p className="text-xs text-gray-500 dark:text-gray-400">
                    Last check: {new Date(autoTriggerStatus.last_check).toLocaleString()}
                  </p>
                )}
              </div>
            </div>
            <button
              onClick={toggleAutoTrigger}
              className={`px-6 py-2 rounded-lg font-medium transition-colors shadow-sm ${
                autoTriggerStatus.enabled
                  ? 'bg-green-600 text-white hover:bg-green-700'
                  : 'bg-gray-300 text-gray-700 hover:bg-gray-400'
              }`}
            >
              {autoTriggerStatus.enabled ? '✓ Enabled' : '⏸ Disabled'}
            </button>
          </div>
        </div>
      )}

      {playbooks.length === 0 ? (
        <div className="text-center py-12 bg-gray-50 dark:bg-gray-900 rounded-lg">
          <Play className="w-12 h-12 text-gray-400 mx-auto mb-4" />
          <p className="text-gray-600 dark:text-gray-400">No playbooks have been created yet</p>
          <p className="text-sm text-gray-500 dark:text-gray-500 mt-2">Create a playbook to automate containment and detection closure.</p>
        </div>
      ) : (
        <div className="space-y-4">
          {playbooks.map((playbook) => (
            <div key={playbook.id} className="border dark:border-gray-700 rounded-lg p-4 hover:shadow-md transition-shadow bg-white dark:bg-gray-800">
              <div className="flex justify-between items-start">
                <div className="flex-1">
                  <h3 className="font-semibold text-lg mb-2 text-gray-800 dark:text-white">{playbook.name}</h3>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-1">
                    Trigger: <span className="font-medium">{playbook.trigger}</span>
                  </p>
                  <p className="text-sm text-gray-600 dark:text-gray-400 mb-2">
                    Actions: <span className="font-medium">{playbook.actions.length}</span>
                  </p>
                  
                  <div className="flex flex-wrap gap-2 mt-2 mb-2">
                    {playbook.actions.map((action, idx) => (
                      <span 
                        key={idx} 
                        className="inline-flex items-center px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded text-xs font-medium"
                      >
                        {action.type === 'contain_host' && '🔒 Contain Host'}
                        {action.type === 'close_detection' && '✓ Close Detection'}
                        {!['contain_host', 'close_detection'].includes(action.type) && action.type}
                      </span>
                    ))}
                  </div>
                  
                  {!playbook.enabled && (
                    <span className="inline-block px-2 py-1 text-xs bg-gray-100 dark:bg-gray-700 text-gray-700 dark:text-gray-300 rounded-full">
                      ⏸ Disabled
                    </span>
                  )}
                  
                  {(playbook.created || playbook.updated) && (
                    <div className="text-xs text-gray-500 dark:text-gray-400 mt-2">
                      {playbook.created && (
                        <span className="mr-3">
                          Created: {new Date(playbook.created).toLocaleDateString()}
                        </span>
                      )}
                      {playbook.updated && (
                        <span>
                          Updated: {new Date(playbook.updated).toLocaleDateString()}
                        </span>
                      )}
                    </div>
                  )}
                </div>
                
                <div className="flex space-x-2 ml-4">
                  <button
                    onClick={() => onExecuteClick(playbook)}
                    className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 transition-colors"
                    title="Execute this playbook"
                  >
                    <Play className="w-4 h-4 mr-2" />
                    Execute
                  </button>
                  <button
                    onClick={() => onDeleteClick(playbook.id)}
                    className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700 transition-colors"
                    title="Delete this playbook"
                  >
                    <Trash2 className="w-4 h-4" />
                  </button>
                </div>
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

const CommentDialog = ({ commentData, setCommentData, onConfirm, onClose }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
      <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Add Comment</h3>
      <textarea
        value={commentData.comment}
        onChange={(e) => setCommentData({ ...commentData, comment: e.target.value })}
        className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg mb-4 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
        rows="4"
        placeholder="Enter your comment..."
      />
      <div className="flex justify-end space-x-2">
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
        <button onClick={onConfirm} className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">Confirm</button>
      </div>
    </div>
  </div>
);

const IOCDialog = ({ onClose, onCreate }) => {
  const [iocData, setIOCData] = useState({
    type: 'ipv4',
    value: '',
    policy: 'detect',
    description: '',
    severity: 'medium',
    tags: [],
  });

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Create Custom IOC</h3>
        <div className="space-y-4">
          <select
            value={iocData.type}
            onChange={(e) => setIOCData({ ...iocData, type: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="ipv4">IPv4 Address</option>
            <option value="domain">Domain</option>
            <option value="md5">MD5 Hash</option>
            <option value="sha256">SHA256 Hash</option>
          </select>
          <input
            type="text"
            placeholder="IOC Value"
            value={iocData.value}
            onChange={(e) => setIOCData({ ...iocData, value: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          />
          <select
            value={iocData.severity}
            onChange={(e) => setIOCData({ ...iocData, severity: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <textarea
            placeholder="Description"
            value={iocData.description}
            onChange={(e) => setIOCData({ ...iocData, description: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            rows="3"
          />
        </div>
        <div className="flex justify-end space-x-2 mt-4">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
          <button onClick={() => onCreate(iocData)} className="px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">Create IOC</button>
        </div>
      </div>
    </div>
  );
};

const PlaybookDialog = ({ onClose, onCreate }) => {
  const [playbookData, setPlaybookData] = useState({
    name: '',
    trigger: 'manual',
    actions: [],
    enabled: true,
    description: '',
  });

  const actionTypes = [
    { id: 'contain_host', label: 'Contain Host', tier: 'Tier 0', color: 'purple', description: 'Network isolate the endpoint', target: 'host', params: [] },
    { id: 'close_detection', label: 'Close Detection', tier: 'Detection', color: 'blue', description: 'Mark detection as closed/false positive', target: 'detection', params: [] },
    { id: 'kill_process', label: 'Kill Process', tier: 'RTR', color: 'red', description: 'Terminate a running process', target: 'host', params: [{ name: 'process', label: 'Process Name/PID', type: 'text', required: true, placeholder: 'e.g., malware.exe or 1234' }] },
    { id: 'delete_file', label: 'Delete File', tier: 'RTR', color: 'orange', description: 'Remove malicious file from disk', target: 'host', params: [{ name: 'path', label: 'File Path', type: 'text', required: true, placeholder: 'e.g., C:\\Temp\\malware.exe' }] },
    { id: 'create_ioc', label: 'Create IOC', tier: 'Intelligence', color: 'green', description: 'Add hash/IP/domain to IOC list', target: 'detection', params: [{ name: 'ioc_type', label: 'IOC Type', type: 'select', options: ['sha256', 'md5', 'sha1', 'ipv4', 'domain'], required: true, default: 'sha256' }, { name: 'severity', label: 'Severity', type: 'select', options: ['critical', 'high', 'medium', 'low', 'informational'], required: true, default: 'medium' }] },
  ];

  const toggleAction = (actionType) => {
    setPlaybookData(prev => {
      const hasAction = prev.actions.some(a => a.type === actionType);
      
      if (hasAction) {
        return { ...prev, actions: prev.actions.filter(a => a.type !== actionType) };
      } else {
        const actionDef = actionTypes.find(a => a.id === actionType);
        const defaultParams = {};
        
        if (actionDef.params) {
          actionDef.params.forEach(param => {
            if (param.default) {
              defaultParams[param.name] = param.default;
            } else if (param.type === 'select' && param.options) {
              defaultParams[param.name] = param.options[0];
            }
          });
        }
        
        const newAction = { type: actionType, params: defaultParams, order: prev.actions.length };
        return { ...prev, actions: [...prev.actions, newAction] };
      }
    });
  };

  const hasAction = (actionType) => {
    return playbookData.actions.some(a => a.type === actionType);
  };

  const updateActionParam = (actionType, paramName, value) => {
    setPlaybookData(prev => ({
      ...prev,
      actions: prev.actions.map(action => 
        action.type === actionType 
          ? { ...action, params: { ...action.params, [paramName]: value } }
          : action
      )
    }));
  };

  const getAction = (actionType) => {
    return playbookData.actions.find(a => a.type === actionType);
  };

  const getActionDef = (actionType) => {
    return actionTypes.find(a => a.id === actionType);
  };

  const validatePlaybook = () => {
    if (!playbookData.name.trim()) return false;
    if (playbookData.actions.length === 0) return false;
    
    for (const action of playbookData.actions) {
      const actionDef = getActionDef(action.type);
      if (actionDef && actionDef.params) {
        for (const param of actionDef.params) {
          if (param.required && !action.params[param.name]) {
            return false;
          }
        }
      }
    }
    return true;
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50 p-4">
      <div className="bg-white dark:bg-gray-800 rounded-lg w-full max-w-4xl max-h-[90vh] flex flex-col">
        <div className="bg-gradient-to-r from-purple-600 to-purple-700 text-white p-6 rounded-t-lg">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold">Create Automated Playbook</h3>
              <p className="text-sm opacity-90 mt-1">Configure actions to automate incident response</p>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white hover:bg-opacity-20 rounded-lg">
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-6">
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Playbook Name *</label>
              <input
                type="text"
                placeholder="e.g., Ransomware Rapid Response"
                value={playbookData.name}
                onChange={(e) => setPlaybookData({ ...playbookData, name: e.target.value })}
                className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Description</label>
              <textarea
                placeholder="Describe when and how this playbook should be used..."
                value={playbookData.description}
                onChange={(e) => setPlaybookData({ ...playbookData, description: e.target.value })}
                className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg focus:ring-2 focus:ring-purple-500 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                rows="2"
              />
            </div>
            
            <div>
              <label className="block text-sm font-semibold text-gray-700 dark:text-gray-300 mb-2">Trigger Type</label>
              <select
                value={playbookData.trigger}
                onChange={(e) => setPlaybookData({ ...playbookData, trigger: e.target.value })}
                className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              >
                <option value="manual">Manual Execution</option>
                <option value="critical_detection">On Critical Detection</option>
                <option value="high_detection">On High Severity Detection</option>
                <option value="ransomware">On Ransomware Detection</option>
              </select>
            </div>
          </div>

          <div>
            <h4 className="text-lg font-bold text-gray-800 dark:text-white mb-3">Actions to Execute *</h4>
            <div className="space-y-3">
              {actionTypes.map((actionDef) => (
                <div 
                  key={actionDef.id}
                  className={`border-2 rounded-lg p-4 transition-all ${
                    hasAction(actionDef.id) ? 'border-purple-500 bg-purple-50 dark:bg-purple-900/30' : 'border-gray-200 dark:border-gray-700'
                  }`}
                >
                  <label className="flex items-start cursor-pointer">
                    <input 
                      type="checkbox" 
                      checked={hasAction(actionDef.id)}
                      onChange={() => toggleAction(actionDef.id)}
                      className="mt-1 mr-3 w-5 h-5" 
                    />
                    <div className="flex-1">
                      <div className="flex items-center flex-wrap gap-2 mb-1">
                        <span className="font-semibold text-gray-800 dark:text-white">{actionDef.label}</span>
                        <span className={`px-2 py-0.5 rounded text-xs font-medium bg-${actionDef.color}-100 dark:bg-${actionDef.color}-900 text-${actionDef.color}-700 dark:text-${actionDef.color}-200`}>
                          {actionDef.tier}
                        </span>
                      </div>
                      <p className="text-sm text-gray-600 dark:text-gray-400">{actionDef.description}</p>
                    </div>
                  </label>

                  {hasAction(actionDef.id) && actionDef.params.length > 0 && (
                    <div className="mt-4 ml-8 space-y-3 border-l-2 border-purple-300 dark:border-purple-700 pl-4">
                      {actionDef.params.map((param) => {
                        const currentAction = getAction(actionDef.id);
                        const currentValue = currentAction?.params[param.name] || '';
                        
                        return (
                          <div key={param.name}>
                            <label className="block text-sm font-medium text-gray-700 dark:text-gray-300 mb-1">
                              {param.label}
                              {param.required && <span className="text-red-500 ml-1">*</span>}
                            </label>
                            
                            {param.type === 'select' ? (
                              <select
                                value={currentValue}
                                onChange={(e) => updateActionParam(actionDef.id, param.name, e.target.value)}
                                className="w-full px-3 py-2 border dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                              >
                                {param.options.map(option => (
                                  <option key={option} value={option}>{option}</option>
                                ))}
                              </select>
                            ) : (
                              <input
                                type="text"
                                value={currentValue}
                                onChange={(e) => updateActionParam(actionDef.id, param.name, e.target.value)}
                                placeholder={param.placeholder || param.label}
                                className="w-full px-3 py-2 border dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                              />
                            )}
                          </div>
                        );
                      })}
                    </div>
                  )}
                </div>
              ))}
            </div>
            
            {playbookData.actions.length === 0 && (
              <div className="mt-4 p-3 bg-yellow-50 dark:bg-yellow-900/30 border border-yellow-200 dark:border-yellow-700 rounded-lg">
                <p className="text-sm text-yellow-800 dark:text-yellow-200">Please select at least one action for this playbook</p>
              </div>
            )}
          </div>

          <div className="border-t dark:border-gray-700 pt-4">
            <label className="flex items-center cursor-pointer">
              <input
                type="checkbox"
                checked={playbookData.enabled}
                onChange={(e) => setPlaybookData({ ...playbookData, enabled: e.target.checked })}
                className="mr-3 w-5 h-5"
              />
              <span className="text-sm font-medium text-gray-700 dark:text-gray-300">Enable playbook immediately after creation</span>
            </label>
          </div>
        </div>
        
        <div className="border-t dark:border-gray-700 p-6 bg-gray-50 dark:bg-gray-900 rounded-b-lg">
          <div className="flex justify-end space-x-3">
            <button onClick={onClose} className="px-6 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
            <button 
              onClick={() => onCreate(playbookData)} 
              disabled={!validatePlaybook()}
              className="px-6 py-2 bg-purple-600 text-white rounded-lg disabled:opacity-50 flex items-center hover:bg-purple-700"
            >
              <Plus className="w-4 h-4 mr-2" />Create Playbook
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const PlaybookExecuteDialog = ({ playbook, detections, hosts, onClose, onRun }) => {
  const [targetType, setTargetType] = useState('detection');
  const [targetId, setTargetId] = useState('');

  useEffect(() => {
    if (targetType === 'detection' && detections.length > 0) {
      setTargetId(detections[0].id);
    } else if (targetType === 'host' && hosts.length > 0) {
      setTargetId(hosts[0].id);
    } else {
      setTargetId('');
    }
  }, [targetType, detections, hosts]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-lg w-full">
        <h3 className="text-xl font-bold mb-2 text-gray-800 dark:text-white">Execute Playbook</h3>
        <p className="text-sm text-gray-600 dark:text-gray-400 mb-4">Playbook: <span className="font-semibold">{playbook?.name}</span></p>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">Target Type</label>
            <select value={targetType} onChange={(e) => setTargetType(e.target.value)} className="w-full px-3 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
              <option value="detection">Detection</option>
              <option value="host">Host</option>
            </select>
          </div>

          <div>
            <label className="block text-sm font-medium mb-1 text-gray-700 dark:text-gray-300">
              {targetType === 'detection' ? 'Select Detection' : 'Select Host'}
            </label>
            {targetType === 'detection' ? (
              detections.length > 0 ? (
                <select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full px-3 py-2 border dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                  {detections.slice(0, 100).map((d) => (
                    <option key={d.id} value={d.id}>
                      {d.name || 'Detection'} – {d.host || 'Host'} – {d.timestamp ? new Date(d.timestamp).toLocaleString() : 'N/A'}
                    </option>
                  ))}
                </select>
              ) : (
                <p className="text-xs text-gray-500 dark:text-gray-400">No detections available</p>
              )
            ) : hosts.length > 0 ? (
              <select value={targetId} onChange={(e) => setTargetId(e.target.value)} className="w-full px-3 py-2 border dark:border-gray-600 rounded-lg text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                {hosts.slice(0, 100).map((h) => (
                  <option key={h.id} value={h.id}>
                    {h.hostname || 'Host'} – {h.ip || 'IP'} – {h.os || 'OS'}
                  </option>
                ))}
              </select>
            ) : (
              <p className="text-xs text-gray-500 dark:text-gray-400">No hosts available</p>
            )}
          </div>
        </div>

        <div className="flex justify-end space-x-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
          <button onClick={() => onRun(targetType, targetId)} disabled={!targetId} className="px-4 py-2 bg-purple-600 text-white rounded-lg disabled:opacity-50 hover:bg-purple-700">
            Run Playbook
          </button>
        </div>
      </div>
    </div>
  );
};

const CloseByHashDialog = ({ onClose, onSubmit, initialHash = '' }) => {
  const [hashData, setHashData] = useState({
    hash: initialHash,
    comment: 'Closed via hash - approved by SOC',
    status: 'closed',
    dry_run: false,
  });

  useEffect(() => {
    setHashData(prev => ({ ...prev, hash: initialHash }));
  }, [initialHash]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Close Detections by SHA256 Hash</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">SHA256 Hash</label>
            <input
              type="text"
              placeholder="Enter SHA256 hash..."
              value={hashData.hash}
              onChange={(e) => setHashData({ ...hashData, hash: e.target.value })}
              className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg font-mono text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Comment</label>
            <textarea
              value={hashData.comment}
              onChange={(e) => setHashData({ ...hashData, comment: e.target.value })}
              className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
              rows="3"
            />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2 text-gray-700 dark:text-gray-300">Status</label>
            <select
              value={hashData.status}
              onChange={(e) => setHashData({ ...hashData, status: e.target.value })}
              className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            >
              <option value="closed">Closed</option>
              <option value="resolved">Resolved</option>
              <option value="in_progress">In Progress</option>
            </select>
          </div>
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={hashData.dry_run}
              onChange={(e) => setHashData({ ...hashData, dry_run: e.target.checked })}
              className="mr-2"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">Dry run (preview only, no changes)</span>
          </label>
        </div>
        <div className="flex justify-end space-x-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
          <button onClick={() => onSubmit(hashData)} className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700">
            {hashData.dry_run ? 'Preview' : 'Close Detections'}
          </button>
        </div>
      </div>
    </div>
  );
};

const HashAnalysisDialog = ({ data, onClose, onCloseHash, onCreateExclusion }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-4xl w-full max-h-[80vh] overflow-hidden flex flex-col">
      <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Hash Analysis Report</h3>
      <div className="bg-gray-50 dark:bg-gray-900 p-4 rounded-lg mb-4">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Total Detections</p>
            <p className="text-2xl font-bold text-gray-800 dark:text-white">{data.total_detections}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Unique Hashes</p>
            <p className="text-2xl font-bold text-gray-800 dark:text-white">{data.unique_hashes}</p>
          </div>
          <div>
            <p className="text-sm text-gray-600 dark:text-gray-400">Most Common</p>
            <p className="text-2xl font-bold text-gray-800 dark:text-white">{data.hashes[0]?.count || 0}</p>
          </div>
        </div>
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full">
          <thead className="bg-gray-100 dark:bg-gray-700 sticky top-0">
            <tr>
              <th className="px-4 py-2 text-left text-sm font-semibold text-gray-700 dark:text-gray-300">Hash</th>
              <th className="px-4 py-2 text-center text-sm font-semibold text-gray-700 dark:text-gray-300">Count</th>
              <th className="px-4 py-2 text-right text-sm font-semibold text-gray-700 dark:text-gray-300">Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.hashes.map((item) => (
              <tr key={item.hash} className="border-b dark:border-gray-700 hover:bg-gray-50 dark:hover:bg-gray-700">
                <td className="px-4 py-3 font-mono text-xs text-gray-800 dark:text-gray-200">{item.hash}</td>
                <td className="px-4 py-3 text-center">
                  <span className="px-2 py-1 bg-blue-100 dark:bg-blue-900 text-blue-800 dark:text-blue-200 rounded-full text-sm font-semibold">
                    {item.count}
                  </span>
                </td>
                <td className="px-4 py-3 text-right">
                  <button
                    onClick={() => onCloseHash(item.hash)}
                    className="px-3 py-1 bg-orange-600 text-white rounded text-sm hover:bg-orange-700 mr-2"
                  >
                    Close All
                  </button>
                  <button
                    onClick={() => onCreateExclusion(item.hash)}
                    className="px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700"
                  >
                    Exclude
                  </button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex justify-end mt-4">
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Close</button>
      </div>
    </div>
  </div>
);

const AdvancedSearchDialog = ({ onClose, onSearch }) => {
  const [filterString, setFilterString] = useState('');
  
  const examples = [
    { label: 'New detections', filter: 'status:"new"' },
    { label: 'High severity', filter: 'max_severity_displayname:"High"' },
    { label: 'Last 24h', filter: 'first_behavior:>"now-24h"' },
  ];

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-2xl w-full">
        <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Advanced FQL Search</h3>
        <textarea
          value={filterString}
          onChange={(e) => setFilterString(e.target.value)}
          className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg font-mono text-sm mb-4 bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          rows="4"
          placeholder='Example: status:"new"+max_severity_displayname:"High"'
        />
        <div className="mb-4">
          <h4 className="text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Quick Examples:</h4>
          <div className="grid grid-cols-3 gap-2">
            {examples.map((ex) => (
              <button
                key={ex.label}
                onClick={() => setFilterString(ex.filter)}
                className="px-3 py-2 bg-gray-100 dark:bg-gray-700 hover:bg-gray-200 dark:hover:bg-gray-600 rounded text-sm text-gray-800 dark:text-gray-200"
              >
                {ex.label}
              </button>
            ))}
          </div>
        </div>
        <div className="flex justify-end space-x-2">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
          <button onClick={() => onSearch(filterString)} className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
            Search
          </button>
        </div>
      </div>
    </div>
  );
};

const IOCExclusionDialog = ({ onClose, onCreate, initialHash = '' }) => {
  const [exclusionData, setExclusionData] = useState({
    hash: initialHash,
    type: 'sha256',
    description: '',
    applied_globally: true,
  });

  useEffect(() => {
    setExclusionData(prev => ({ ...prev, hash: initialHash }));
  }, [initialHash]);

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4 text-gray-800 dark:text-white">Create IOC Exclusion</h3>
        <div className="space-y-4">
          <select
            value={exclusionData.type}
            onChange={(e) => setExclusionData({ ...exclusionData, type: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          >
            <option value="sha256">SHA256</option>
            <option value="sha1">SHA1</option>
            <option value="md5">MD5</option>
          </select>
          <input
            type="text"
            placeholder="Enter hash..."
            value={exclusionData.hash}
            onChange={(e) => setExclusionData({ ...exclusionData, hash: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg font-mono text-sm bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
          />
          <textarea
            value={exclusionData.description}
            onChange={(e) => setExclusionData({ ...exclusionData, description: e.target.value })}
            className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            rows="3"
            placeholder="Why is this being excluded?"
          />
          <label className="flex items-center">
            <input
              type="checkbox"
              checked={exclusionData.applied_globally}
              onChange={(e) => setExclusionData({ ...exclusionData, applied_globally: e.target.checked })}
              className="mr-2"
            />
            <span className="text-sm text-gray-700 dark:text-gray-300">Apply globally to all hosts</span>
          </label>
        </div>
        <div className="flex justify-end space-x-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
          <button
            onClick={() => onCreate(exclusionData)}
            disabled={!exclusionData.hash || !exclusionData.description}
            className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50"
          >
            Create Exclusion
          </button>
        </div>
      </div>
    </div>
  );
};

const ReportDialog = ({ onClose, onGenerate, detections, hosts, iocs, dashboardStats }) => {
  const [reportConfig, setReportConfig] = useState({
    type: 'executive',
    format: 'pdf',
    timeRange: '24h',
    includeCharts: true,
    includeSummary: true,
    includeDetections: true,
    includeHosts: true, 
    includeIOCs: true, 
    severityFilter: 'all',
    title: 'Security Operations Report',
    deliveryMode: 'download',
    recipients: '',
    emailBody: 'Please find the attached Falcon Manager Pro report.',
  });

  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg max-w-2xl w-full max-h-[90vh] overflow-hidden flex flex-col m-4">
        <div className="bg-gradient-to-r from-purple-600 to-purple-700 text-white p-6">
          <div className="flex items-center justify-between">
            <div>
              <h3 className="text-2xl font-bold">Generate Security Report</h3>
              <p className="text-sm opacity-90 mt-1">Customize and generate comprehensive security reports</p>
            </div>
            <button onClick={onClose} className="p-2 hover:bg-white hover:bg-opacity-20 rounded-lg">
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        <div className="flex-1 overflow-y-auto p-6 space-y-4">
          <div>
            <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Report Type</label>
            <select value={reportConfig.type} onChange={(e) => setReportConfig({ ...reportConfig, type: e.target.value })} className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
              <option value="executive">Executive Summary</option>
              <option value="detailed">Detailed Analysis</option>
              <option value="compliance">Compliance Report</option>
            </select>
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Time Range</label>
              <select value={reportConfig.timeRange}
                      onChange={(e) => setReportConfig({ ...reportConfig, timeRange: e.target.value })}
                      className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                  <option value="1h">Last 1 Hour</option>
                  <option value="6h">Last 6 Hours</option>
                  <option value="12h">Last 12 Hours</option>
                  <option value="24h">Last 24 Hours</option>
                  <option value="2d">Last 2 Days</option>
                  <option value="7d">Last 7 Days</option>
                  <option value="30d">Last 30 Days</option>
              </select>
            </div>

            <div>
              <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Export Format</label>
              <select value={reportConfig.format} onChange={(e) => setReportConfig({ ...reportConfig, format: e.target.value })} className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white">
                <option value="pdf">PDF Document</option>
                <option value="csv">CSV Spreadsheet</option>
                <option value="json">JSON Data</option>
              </select>
            </div>
          </div>

          <div>
            <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Report Title</label>
            <input
              type="text"
              value={reportConfig.title}
              onChange={(e) => setReportConfig({ ...reportConfig, title: e.target.value })}
              className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
            />
          </div>
        <div>
            <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">Delivery</label>
            <div className="flex items-center space-x-4">
              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  value="download"
                  checked={reportConfig.deliveryMode === 'download'}
                  onChange={(e) =>
                    setReportConfig({ ...reportConfig, deliveryMode: e.target.value })
                  }
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Download in browser</span>
              </label>

              <label className="flex items-center space-x-2">
                <input
                  type="radio"
                  value="email"
                  checked={reportConfig.deliveryMode === 'email'}
                  onChange={(e) =>
                    setReportConfig({ ...reportConfig, deliveryMode: e.target.value })
                  }
                />
                <span className="text-sm text-gray-700 dark:text-gray-300">Email via relay</span>
              </label>
            </div>
          </div>

          {reportConfig.deliveryMode === 'email' && (
            <>
              <div>
                <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">
                  Recipient Email(s)
                </label>
                <input
                  type="text"
                  value={reportConfig.recipients}
                  onChange={(e) =>
                    setReportConfig({ ...reportConfig, recipients: e.target.value })
                  }
                  className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  placeholder="user@example.com, another@example.com"
                />
              </div>

              <div>
                <label className="block text-sm font-semibold mb-2 text-gray-700 dark:text-gray-300">
                  Email Message
                </label>
                <textarea
                  value={reportConfig.emailBody}
                  onChange={(e) =>
                    setReportConfig({ ...reportConfig, emailBody: e.target.value })
                  }
                  className="w-full px-4 py-2 border dark:border-gray-600 rounded-lg bg-white dark:bg-gray-700 text-gray-900 dark:text-white"
                  rows={3}
                />
              </div>
            </>
          )}
        </div>

        <div className="border-t dark:border-gray-700 p-6 bg-gray-50 dark:bg-gray-900">
          <div className="flex justify-end space-x-3">
            <button onClick={onClose} className="px-6 py-2 bg-gray-200 dark:bg-gray-700 text-gray-800 dark:text-gray-200 rounded-lg hover:bg-gray-300 dark:hover:bg-gray-600">Cancel</button>
            <button onClick={() => onGenerate(reportConfig)} className="px-6 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700 flex items-center">
              <Download className="w-4 h-4 mr-2" />Generate Report
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

const RTROutputDialog = ({ title, data, onClose }) => {
  const [copied, setCopied] = useState(false);
  const pretty = typeof data === 'string' ? data : JSON.stringify(data, null, 2);

  const handleCopy = async () => {
    try {
      await navigator.clipboard.writeText(pretty);
      setCopied(true);
      setTimeout(() => setCopied(false), 2000);
    } catch (err) {
      console.error('Failed to copy:', err);
      // Fallback for older browsers
      const textArea = document.createElement('textarea');
      textArea.value = pretty;
      textArea.style.position = 'fixed';
      textArea.style.left = '-999999px';
      document.body.appendChild(textArea);
      textArea.select();
      try {
        document.execCommand('copy');
        setCopied(true);
        setTimeout(() => setCopied(false), 2000);
      } catch (err2) {
        console.error('Fallback copy failed:', err2);
      }
      document.body.removeChild(textArea);
    }
  };

  return (
    <div className="fixed inset-0 bg-black bg-opacity-60 flex items-center justify-center z-50">
      <div className="bg-white dark:bg-gray-800 rounded-lg shadow-xl max-w-4xl w-full max-h-[80vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b dark:border-gray-700">
          <h3 className="text-lg font-bold text-gray-800 dark:text-white">{title}</h3>
          <button onClick={onClose} className="p-1 rounded hover:bg-gray-100 dark:hover:bg-gray-700">
            <X className="w-5 h-5 text-gray-600 dark:text-gray-400" />
          </button>
        </div>

        <div className="flex-1 overflow-auto p-4 bg-gray-900">
          <pre className="text-xs text-green-200 whitespace-pre-wrap break-all font-mono">
            {pretty}
          </pre>
        </div>

        <div className="px-4 py-3 border-t dark:border-gray-700 bg-gray-50 dark:bg-gray-900 flex justify-between items-center">
          <div className="text-xs text-gray-600 dark:text-gray-400">
            {pretty.split('\n').length} lines • {(new Blob([pretty]).size / 1024).toFixed(2)} KB
          </div>
          <div className="flex space-x-2">
            <button 
              onClick={handleCopy}
              className={`flex items-center px-4 py-2 rounded-lg text-sm font-medium transition-all ${
                copied 
                  ? 'bg-green-600 text-white' 
                  : 'bg-blue-600 text-white hover:bg-blue-700'
              }`}
            >
              {copied ? (
                <>
                  <Check className="w-4 h-4 mr-2" />
                  Copied!
                </>
              ) : (
                <>
                  <Copy className="w-4 h-4 mr-2" />
                  Copy to Clipboard
                </>
              )}
            </button>
            <button 
              onClick={onClose} 
              className="px-4 py-2 bg-gray-200 dark:bg-gray-700 rounded-lg text-sm text-gray-800 dark:text-gray-200 hover:bg-gray-300 dark:hover:bg-gray-600"
            >
              Close
            </button>
          </div>
        </div>
      </div>
    </div>
  );
};

// Assumes you already imported these icons at the top of your file:
// import { Activity, Clock, AlertTriangle, Shield, TrendingUp, Search, CheckSquare, Zap, BookOpen, Server, Terminal, Database, AlertCircle, Hash, Globe, Play, List, RefreshCw, CheckCircle, Book, Lightbulb, ExternalLink, Command, X } from "lucide-react";

const HelpSidebar = ({ activeTab, onClose, onChangeTab }) => {
  const helpContent = {
    dashboard: {
      title: "Security Analytics Dashboard",
      sections: [
        {
          title: "Overview",
          icon: Activity,
          content: [
            "The dashboard provides real-time security analytics and threat intelligence visualization.",
            "All data auto-refreshes every 30 seconds to ensure you have the latest information."
          ]
        },
        {
          title: "Time Range Selection",
          icon: Clock,
          content: [
            "Use the time range selector to view detections from 1 hour to 30 days.",
            "Shorter time ranges (1-24h) show hourly buckets for granular analysis.",
            "Longer time ranges use 4-hour or daily buckets for better visualization."
          ]
        },
        {
          title: "Severity Cards",
          icon: AlertTriangle,
          content: [
            "Critical/High severity detections require immediate attention.",
            "Click on any severity card to filter the detection list.",
            "Color coding: Red (Critical) → Orange (High) → Yellow (Medium) → Blue (Low)"
          ]
        },
        {
          title: "MITRE ATT&CK Matrix",
          icon: Shield,
          content: [
            "Visualizes adversary tactics and techniques based on your detections.",
            "Click any technique badge to view details on attack.mitre.org.",
            "Heatmap intensity shows frequency of each tactic across detections."
          ]
        },
        {
          title: "Understanding Detection Timeline",
          icon: TrendingUp,
          content: [
            "Hover over timeline bars to see exact counts by severity.",
            "Stacked bars show the composition of detections over time.",
            "Look for spikes that might indicate attack campaigns or system issues."
          ]
        }
      ]
    },
    detections: {
      title: "Detection Management",
      sections: [
        {
          title: "Search & Filter",
          icon: Search,
          content: [
            "Use the search box to find detections by name, host, or behavior.",
            "Filter by severity using the dropdown menu.",
            "Advanced Search (FQL) allows complex queries like: status:\"new\"+max_severity_displayname:\"High\""
          ]
        },
        {
          title: "Bulk Operations",
          icon: CheckSquare,
          content: [
            "Select multiple detections using checkboxes.",
            "Use 'Select All' to choose all visible detections.",
            "Bulk actions: Resolve, Close (False Positive), or Ignore multiple detections at once."
          ]
        },
        {
          title: "Detection Actions",
          icon: Zap,
          content: [
            "Resolve: Mark as True Positive and document remediation.",
            "Close (FP): Mark as False Positive to tune detection rules.",
            "Ignore: Temporarily ignore low-priority detections.",
            "Always add meaningful comments to track investigation history."
          ]
        },
        {
          title: "MITRE ATT&CK Integration",
          icon: Shield,
          content: [
            "Each detection shows mapped MITRE tactics and techniques.",
            "Click technique badges to view detailed ATT&CK framework documentation.",
            "Use this intelligence to understand attack patterns and prioritize response."
          ]
        },
        {
          title: "Best Practices",
          icon: BookOpen,
          content: [
            "Review Critical/High severity detections within 1 hour.",
            "Document all actions with detailed comments for audit trails.",
            "Use Hash Analysis to identify mass false positives.",
            "Close detections in batch when you identify benign patterns."
          ]
        }
      ]
    },
    hosts: {
      title: "Host Management & RTR",
      sections: [
        {
          title: "Host Overview",
          icon: Server,
          content: [
            "Shows all hosts with CrowdStrike Falcon agent installed.",
            "Status indicators: Online (green) / Offline (gray) / Contained (purple).",
            "Use 'Force Refresh' to pull latest data from CrowdStrike API.",
            "Filter by platform (Windows/Linux/Mac) for targeted operations."
          ]
        },
        {
          title: "Network Containment",
          icon: Shield,
          content: [
            "Network Contain: Isolates host from network while keeping Falcon connected.",
            "Use for confirmed compromises to prevent lateral movement.",
            "Host can still communicate with Falcon cloud for remediation.",
            "Lift Containment once threat is neutralized and verified clean."
          ]
        },
        {
          title: "Real-Time Response (RTR) Tiers",
          icon: Terminal,
          content: [
            "Tier 1 (Read-Only): Safe reconnaissance commands (ls, ps, netstat, filehash).",
            "Tier 2 (Active Responder): File operations (get-file, memdump, reg-query).",
            "Tier 3 (Admin): Destructive commands (kill, delete, runscript, restart).",
            "Always verify target host before executing Tier 3 commands."
          ]
        },
        {
          title: "RTR Investigation Workflow",
          icon: Search,
          content: [
            "1. Use 'ps' to list running processes and identify suspicious activity.",
            "2. Use 'netstat' to check active network connections.",
            "3. Use 'filehash' to get SHA256 of suspicious files.",
            "4. Use 'get-file' to retrieve malicious files for analysis.",
            "5. Use 'kill' to terminate malicious processes.",
            "6. Use 'delete-file' to remove malware from disk."
          ]
        },
        {
          title: "Registry Operations",
          icon: Database,
          content: [
            "reg-query: Read registry keys (persistence checks).",
            "reg-set: Modify registry values (remediation).",
            "reg-delete: Remove malicious registry keys.",
            "Common persistence locations: HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
          ]
        },
        {
          title: "RTR Best Practices",
          icon: AlertTriangle,
          content: [
            "Always document RTR actions in incident response notes.",
            "Use read-only commands first before taking destructive actions.",
            "Verify file hashes against VirusTotal before deletion.",
            "Create memory dumps before killing suspicious processes.",
            "Test scripts on non-production systems first."
          ]
        }
      ]
    },
    iocs: {
      title: "IOC Management",
      sections: [
        {
          title: "Custom IOCs",
          icon: AlertCircle,
          content: [
            "Create custom indicators for threats specific to your environment.",
            "Supported types: IPv4, Domain, MD5, SHA1, SHA256.",
            "Policy modes: Detect (alert only) vs Prevent (block).",
            "Tags help organize IOCs by campaign, threat actor, or category."
          ]
        },
        {
          title: "IOC Exclusions",
          icon: Shield,
          content: [
            "Use exclusions for known-good files that trigger false positives.",
            "Apply globally to prevent alerts across all hosts.",
            "Always document WHY an exclusion is needed.",
            "Review exclusions quarterly to ensure they're still valid."
          ]
        },
        {
          title: "VirusTotal Integration",
          icon: Search,
          content: [
            "Click 'Check VirusTotal' on any hash IOC for threat intelligence.",
            "Detection Ratio: Shows how many engines flagged it as malicious.",
            "Verdict interpretation: 10+ = Malicious, 3-10 = Suspicious, 1-3 = Possibly Malicious, 0 = Clean.",
            "Configure VirusTotal API key in login screen for this feature."
          ]
        },
        {
          title: "Hash Analysis Workflow",
          icon: Hash,
          content: [
            "1. Use Hash Analysis tool to find duplicate detections.",
            "2. Click 'Check VirusTotal' on top hashes for validation.",
            "3. For clean hashes with many detections, use 'Close All'.",
            "4. For persistent false positives, create an IOC Exclusion.",
            "5. For malware, add to IOC list with 'Prevent' policy."
          ]
        },
        {
          title: "IOC Sources",
          icon: Globe,
          content: [
            "Threat Intelligence Feeds: MISP, AlienVault OTX, Recorded Future.",
            "Internal IR: Hashes/IPs discovered during incident investigations.",
            "Industry Sharing: ISACs, sector-specific threat groups.",
            "Research: Personal malware analysis and reverse engineering.",
            "Always validate IOCs before adding to prevent false positives."
          ]
        }
      ]
    },
    playbooks: {
      title: "Playbook Automation",
      sections: [
        {
          title: "What are Playbooks?",
          icon: Play,
          content: [
            "Playbooks automate repetitive security response actions.",
            "Chain multiple actions together for consistent incident handling.",
            "Reduce Mean Time To Respond (MTTR) by automating containment.",
            "Ensure compliance with documented, repeatable procedures."
          ]
        },
        {
          title: "Playbook Triggers",
          icon: Zap,
          content: [
            "Manual: Execute on-demand for specific detections/hosts.",
            "Critical Detection: Auto-run when Critical severity detections appear.",
            "High Detection: Auto-run for High severity detections.",
            "Ransomware: Specialized trigger for ransomware indicators."
          ]
        },
        {
          title: "Available Actions",
          icon: List,
          content: [
            "Contain Host: Network isolate endpoint (Tier 0).",
            "Close Detection: Mark as False Positive or Resolved.",
            "Kill Process: Terminate malicious processes (RTR).",
            "Delete File: Remove malware from disk (RTR).",
            "Create IOC: Add indicators to blocklist automatically."
          ]
        },
        {
          title: "Auto-Trigger System",
          icon: RefreshCw,
          content: [
            "Checks for new detections every 30 seconds.",
            "Executes enabled playbooks matching trigger conditions.",
            "Shows processed count and last check time.",
            "Toggle on/off with the Enable/Disable button.",
            "Monitor logs for automatic playbook executions."
          ]
        },
        {
          title: "Playbook Best Practices",
          icon: CheckCircle,
          content: [
            "Test playbooks manually before enabling auto-trigger.",
            "Start with 'Detect' actions before 'Prevent' to avoid disruption.",
            "Document playbook purpose and expected outcomes.",
            "Review playbook logs weekly to tune false positives.",
            "Disable playbooks during maintenance windows.",
            "Have rollback procedures for containment actions."
          ]
        },
        {
          title: "Example Playbooks",
          icon: BookOpen,
          content: [
            "Ransomware Response: Contain host → Kill process → Create IOC → Alert SOC.",
            "False Positive Cleanup: Close detection → Add exclusion → Document reason.",
            "Credential Theft: Contain host → Dump memory → Force password reset.",
            "Cryptominer Detection: Kill process → Delete file → Block C2 domain.",
            "Lateral Movement: Contain host → Capture network traffic → Alert IR team."
          ]
        }
      ]
    }
  };

  const currentHelp = helpContent[activeTab] || helpContent.dashboard;

  return (
    <>
      {/* Backdrop */}
      <div
        className="fixed inset-0 bg-black bg-opacity-50 z-40"
        onClick={onClose}
      />

      {/* Sidebar */}
      <div className="fixed right-0 top-0 h-full w-full max-w-3xl bg-white dark:bg-gray-800 shadow-2xl z-50 overflow-y-auto">
        {/* Header */}
        <div className="sticky top-0 bg-gradient-to-r from-blue-600 to-blue-700 text-white p-6 shadow-md z-10">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-3">
              <Book className="w-8 h-8" />
              <div>
                <h2 className="text-2xl font-bold">{currentHelp.title}</h2>
                <p className="text-sm opacity-90">
                  Documentation & Best Practices
                </p>
              </div>
            </div>
            <button
              onClick={onClose}
              className="p-2 hover:bg-white hover:bg-opacity-20 rounded-lg transition-colors"
              title="Close help"
            >
              <X className="w-6 h-6" />
            </button>
          </div>
        </div>

        {/* Tab Navigation */}
        <div className="bg-gray-100 dark:bg-gray-900 px-6 py-3 border-b dark:border-gray-700">
          <div className="flex flex-wrap gap-2">
            {Object.keys(helpContent).map((tab) => (
              <button
                key={tab}
                onClick={() => onChangeTab && onChangeTab(tab)}
                className={`px-3 py-1.5 rounded-lg text-sm font-medium transition-colors ${
                  activeTab === tab
                    ? "bg-blue-600 text-white"
                    : "bg-white dark:bg-gray-800 text-gray-700 dark:text-gray-300 hover:bg-gray-200 dark:hover:bg-gray-700"
                }`}
              >
                {helpContent[tab].title}
              </button>
            ))}
          </div>
        </div>

        {/* Content Sections */}
        <div className="p-6 space-y-6">
          {currentHelp.sections.map((section, idx) => {
            const IconComponent = section.icon;
            return (
              <div
                key={idx}
                className="bg-gradient-to-br from-blue-50 to-indigo-50 dark:from-blue-900/20 dark:to-indigo-900/20 border border-blue-200 dark:border-blue-800 rounded-lg p-5"
              >
                <div className="flex items-center space-x-3 mb-4">
                  <div className="p-2 bg-blue-600 rounded-lg">
                    <IconComponent className="w-5 h-5 text-white" />
                  </div>
                  <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                    {section.title}
                  </h3>
                </div>
                <div className="space-y-3">
                  {section.content.map((item, itemIdx) => (
                    <div
                      key={itemIdx}
                      className="flex items-start space-x-3"
                    >
                      <div className="flex-shrink-0 w-1.5 h-1.5 rounded-full bg-blue-600 mt-2" />
                      <p className="text-sm text-gray-700 dark:text-gray-300 leading-relaxed">
                        {item}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            );
          })}

          {/* Quick Tips Section - Always visible */}
          <div className="bg-yellow-50 dark:bg-yellow-900/20 border border-yellow-200 dark:border-yellow-800 rounded-lg p-5">
            <div className="flex items-center space-x-3 mb-4">
              <Lightbulb className="w-6 h-6 text-yellow-600 dark:text-yellow-400" />
              <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                Pro Tips
              </h3>
            </div>
            <div className="space-y-2 text-sm text-gray-700 dark:text-gray-300">
              <p>
                💡 Use{" "}
                <kbd className="px-2 py-1 bg-white dark:bg-gray-800 rounded border dark:border-gray-700 font-mono text-xs">
                  Ctrl+F
                </kbd>{" "}
                to search within help documentation
              </p>
              <p>⚡ All data auto-refreshes every 30 seconds - no manual refresh needed</p>
              <p>🔍 Use Advanced Search for complex FQL queries across detections</p>
              <p>🎯 Click Hash Analysis to find and close duplicate false positives in bulk</p>
              <p>🔐 Network Contain isolates hosts while keeping Falcon connected for remediation</p>
              <p>📊 Generate reports in PDF/CSV format and email them automatically</p>
            </div>
          </div>

          {/* External Resources */}
          <div className="bg-gray-50 dark:bg-gray-900 border border-gray-200 dark:border-gray-700 rounded-lg p-5">
            <div className="flex items-center space-x-3 mb-4">
              <ExternalLink className="w-6 h-6 text-gray-600 dark:text-gray-400" />
              <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                External Resources
              </h3>
            </div>
            <div className="space-y-2">
              <a
                href="https://www.crowdstrike.com/resources/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline"
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                CrowdStrike Documentation
              </a>
              <a
                href="https://attack.mitre.org/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline"
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                MITRE ATT&CK Framework
              </a>
              <a
                href="https://www.virustotal.com/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline"
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                VirusTotal Threat Intelligence
              </a>
              <a
                href="https://falcon.crowdstrike.com/documentation/"
                target="_blank"
                rel="noopener noreferrer"
                className="flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline"
              >
                <ExternalLink className="w-4 h-4 mr-2" />
                Falcon API Documentation
              </a>
            </div>
          </div>

          {/* Keyboard Shortcuts */}
          <div className="bg-purple-50 dark:bg-purple-900/20 border border-purple-200 dark:border-purple-800 rounded-lg p-5">
            <div className="flex items-center space-x-3 mb-4">
              <Command className="w-6 h-6 text-purple-600 dark:text-purple-400" />
              <h3 className="text-lg font-bold text-gray-900 dark:text-white">
                Keyboard Shortcuts
              </h3>
            </div>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3 text-sm">
              <div className="flex items-center justify-between">
                <span className="text-gray-700 dark:text-gray-300">
                  Search Detections
                </span>
                <kbd className="px-2 py-1 bg-white dark:bg-gray-800 rounded border dark:border-gray-700 font-mono text-xs">
                  Ctrl+F
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-700 dark:text-gray-300">
                  Toggle Dark Mode
                </span>
                <kbd className="px-2 py-1 bg-white dark:bg-gray-800 rounded border dark:border-gray-700 font-mono text-xs">
                  D
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-700 dark:text-gray-300">
                  Open Help
                </span>
                <kbd className="px-2 py-1 bg-white dark:bg-gray-800 rounded border dark:border-gray-700 font-mono text-xs">
                  ?
                </kbd>
              </div>
              <div className="flex items-center justify-between">
                <span className="text-gray-700 dark:text-gray-300">
                  Select All
                </span>
                <kbd className="px-2 py-1 bg-white dark:bg-gray-800 rounded border dark:border-gray-700 font-mono text-xs">
                  Ctrl+A
                </kbd>
              </div>
            </div>
          </div>
        </div>

        {/* Footer */}
        <div className="border-t dark:border-gray-700 bg-gray-50 dark:bg-gray-900 p-6 text-center">
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Falcon Manager Pro v2.0 • Built for Security Operations Teams
          </p>
          <p className="text-xs text-gray-500 dark:text-gray-500 mt-1">
            Need help? Contact your security team or open a support ticket.
          </p>
        </div>
      </div>
    </>
  );
};



// Export statement at the end of your App.js file
export default FalconDashboard;