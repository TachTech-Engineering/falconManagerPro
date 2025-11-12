import React, { useState, useEffect, useCallback } from 'react';
import {
  AlertTriangle,
  Shield,
  Activity,
  Server,
  Search,
  RefreshCw,
  AlertCircle,
  Download,
  Plus,
  Play,
  Save,
  Eye,
} from 'lucide-react';

const API_BASE = '/api';

const FalconDashboard = () => {
  const [activeTab, setActiveTab] = useState('dashboard');
  const [isAuthenticated, setIsAuthenticated] = useState(() => {
    // Check sessionStorage on initial load
    return sessionStorage.getItem('falcon_authenticated') === 'true';
  });
  const [credentials, setCredentials] = useState(() => {
    // Try to load credentials from sessionStorage
    const saved = sessionStorage.getItem('falcon_credentials');
    if (saved) {
      return JSON.parse(saved);
    }
    return {
      clientId: '',
      clientSecret: '',
      baseUrl: 'https://api.crowdstrike.com',
    };
  });

  const [detections, setDetections] = useState([]);
  const [hosts, setHosts] = useState([]);
  const [iocs, setIOCs] = useState([]);
  const [playbooks, setPlaybooks] = useState([]);
  const [savedViews, setSavedViews] = useState([]);

  const [searchQuery, setSearchQuery] = useState('');
  const [selectedSeverity, setSelectedSeverity] = useState('all');
  const [selectedDetections, setSelectedDetections] = useState([]);
  const [showCommentDialog, setShowCommentDialog] = useState(false);
  const [commentData, setCommentData] = useState({
    detectionId: null,
    action: '',
    comment: '',
  });
  const [showIOCDialog, setShowIOCDialog] = useState(false);
  const [showPlaybookDialog, setShowPlaybookDialog] = useState(false);
  const [showViewDialog, setShowViewDialog] = useState(false);
  const [notification, setNotification] = useState(null);
  const [showHashDialog, setShowHashDialog] = useState(false);
  const [showHashAnalysisDialog, setShowHashAnalysisDialog] = useState(false);
  const [showAdvancedSearchDialog, setShowAdvancedSearchDialog] = useState(false);
  const [showExclusionDialog, setShowExclusionDialog] = useState(false);
  const [hashAnalysis, setHashAnalysis] = useState(null);
  const [dashboardStats, setDashboardStats] = useState(null);

  const showNotification = (message, type = 'success') => {
    setNotification({ message, type });
    setTimeout(() => setNotification(null), 3000);
  };

  const fetchDetections = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/detections?hours=24`);
      const data = await response.json();
      if (data.detections) setDetections(data.detections);
    } catch (error) {
      console.error('Error fetching detections:', error);
    }
  }, []);

  const fetchHosts = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/hosts`);
      const data = await response.json();
      if (data.hosts) setHosts(data.hosts);
    } catch (error) {
      console.error('Error fetching hosts:', error);
    }
  }, []);

  const fetchIOCs = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/iocs`);
      const data = await response.json();
      if (data.iocs) setIOCs(data.iocs);
    } catch (error) {
      console.error('Error fetching IOCs:', error);
    }
  }, []);

  const fetchPlaybooks = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/playbooks`);
      const data = await response.json();
      if (data.playbooks) setPlaybooks(data.playbooks);
    } catch (error) {
      console.error('Error fetching playbooks:', error);
    }
  }, []);

  const fetchSavedViews = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/views`);
      const data = await response.json();
      if (data.views) setSavedViews(data.views);
    } catch (error) {
      console.error('Error fetching views:', error);
    }
  }, []);

  const fetchDashboardStats = useCallback(async () => {
    try {
      const response = await fetch(`${API_BASE}/detections?hours=24`);
      const data = await response.json();
      if (data.detections) {
        const stats = calculateDashboardStats(data.detections);
        setDashboardStats(stats);
      }
    } catch (error) {
      console.error('Error fetching dashboard stats:', error);
    }
  }, []);

  const calculateDashboardStats = (detections) => {
    const now = new Date();
    
    const severityCounts = {
      critical: 0,
      high: 0,
      medium: 0,
      low: 0,
      unknown: 0
    };
    
    const statusCounts = {
      new: 0,
      in_progress: 0,
      true_positive: 0,
      false_positive: 0,
      closed: 0,
      ignored: 0
    };
    
    // Create 24 hourly buckets for the last 24 hours
    const timelineData = [];
    for (let i = 23; i >= 0; i--) {
      const bucketTime = new Date(now.getTime() - i * 60 * 60 * 1000);
      timelineData.push({
        time: bucketTime,
        hour: bucketTime.getHours(),
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        unknown: 0,
        total: 0
      });
    }
    
    detections.forEach(det => {
      const severity = (det.severity || 'unknown').toLowerCase();
      const status = (det.status || 'new').toLowerCase();
      
      severityCounts[severity] = (severityCounts[severity] || 0) + 1;
      statusCounts[status] = (statusCounts[status] || 0) + 1;
      
      if (det.timestamp) {
        const detTime = new Date(det.timestamp);
        const hoursSinceDetection = (now - detTime) / (60 * 60 * 1000);
        
        if (hoursSinceDetection >= 0 && hoursSinceDetection < 24) {
          const bucketIndex = Math.floor(hoursSinceDetection);
          const timelineBucket = timelineData[23 - bucketIndex];
          
          if (timelineBucket && severity in timelineBucket) {
            timelineBucket[severity]++;
            timelineBucket.total++;
          }
        }
      }
    });
    
    return {
      severityCounts,
      statusCounts,
      timelineData,
      totalDetections: detections.length
    };
  };

  const fetchAllData = useCallback(() => {
    fetchDetections();
    fetchHosts();
    fetchIOCs();
    fetchPlaybooks();
    fetchSavedViews();
  }, [fetchDetections, fetchHosts, fetchIOCs, fetchPlaybooks, fetchSavedViews]);

  useEffect(() => {
    if (isAuthenticated) {
      fetchAllData();
      if (activeTab === 'dashboard') {
        fetchDashboardStats();
      }
      const pollInterval = setInterval(() => {
        fetchDetections();
        fetchHosts();
        if (activeTab === 'dashboard') {
          fetchDashboardStats();
        }
      }, 30000);
      return () => clearInterval(pollInterval);
    }
  }, [isAuthenticated, fetchAllData, fetchDetections, fetchHosts, fetchDashboardStats, activeTab]);

  // Re-authenticate with backend on page load if credentials exist
  useEffect(() => {
    const reAuthenticate = async () => {
      if (isAuthenticated && credentials.clientId && credentials.clientSecret) {
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
          if (data.status !== 'success') {
            // Backend auth failed, clear session
            setIsAuthenticated(false);
            sessionStorage.removeItem('falcon_authenticated');
            sessionStorage.removeItem('falcon_credentials');
          }
        } catch (error) {
          console.error('Re-authentication failed:', error);
          setIsAuthenticated(false);
          sessionStorage.removeItem('falcon_authenticated');
          sessionStorage.removeItem('falcon_credentials');
        }
      }
    };
    reAuthenticate();
  }, []);

  const handleLogin = async () => {
    if (credentials.clientId && credentials.clientSecret) {
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
        if (data.status === 'success') {
          setIsAuthenticated(true);
          sessionStorage.setItem('falcon_authenticated', 'true');
          sessionStorage.setItem('falcon_credentials', JSON.stringify(credentials));
          fetchAllData();
        } else {
          alert('Authentication failed: ' + data.message);
        }
      } catch (error) {
        alert('Error connecting to backend: ' + error.message);
      }
    }
  };

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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(body),
      });
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
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          detection_ids: selectedDetections,
          status,
          comment,
        }),
      });
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

  const handleCreateIOC = async (iocData) => {
    try {
      const response = await fetch(`${API_BASE}/iocs`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(iocData),
      });
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

  const handleCreatePlaybook = async (playbookData) => {
    try {
      const response = await fetch(`${API_BASE}/playbooks`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(playbookData),
      });
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

  const handleExecutePlaybook = async (playbookId, targetId) => {
    try {
      const response = await fetch(`${API_BASE}/playbooks/${playbookId}/execute`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ target_id: targetId }),
      });
      if (response.ok) {
        showNotification('Playbook executed successfully');
      } else {
        showNotification('Failed to execute playbook', 'error');
      }
    } catch (error) {
      console.error('Error executing playbook:', error);
    }
  };

  const handleSaveView = async (viewData) => {
    try {
      const response = await fetch(`${API_BASE}/views`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(viewData),
      });
      if (response.ok) {
        setShowViewDialog(false);
        fetchSavedViews();
        showNotification('View saved successfully');
      } else {
        showNotification('Failed to save view', 'error');
      }
    } catch (error) {
      console.error('Error saving view:', error);
    }
  };

  const handleGenerateReport = async (reportType) => {
    try {
      const response = await fetch(`${API_BASE}/reports/generate`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ type: reportType, time_range: 24 }),
      });
      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `falcon_report_${reportType}_${Date.now()}.pdf`;
        a.click();
        showNotification('Report generated successfully');
      } else {
        showNotification('Failed to generate report', 'error');
      }
    } catch (error) {
      console.error('Error generating report:', error);
    }
  };

  const handleCloseByHash = async (hashData) => {
    try {
      const response = await fetch(`${API_BASE}/detections/close-by-hash`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(hashData),
      });
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
      const response = await fetch(`${API_BASE}/detections/hash-summary?filter=status:"new"&limit=10000`);
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
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ filter: filterString, limit: 100 }),
      });
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
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(exclusionData),
      });
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

  const toggleDetectionSelection = (detectionId) => {
    setSelectedDetections((prev) =>
      prev.includes(detectionId)
        ? prev.filter((id) => id !== detectionId)
        : [...prev, detectionId]
    );
  };

  const getSeverityColor = (severity) => {
    switch (severity) {
      case 'critical': return 'text-red-600 bg-red-50';
      case 'high': return 'text-orange-600 bg-orange-50';
      case 'medium': return 'text-yellow-600 bg-yellow-50';
      case 'low': return 'text-blue-600 bg-blue-50';
      default: return 'text-gray-600 bg-gray-50';
    }
  };

  const handleKillProcess = async (hostId) => {
    const processName = window.prompt(`Enter the process name or PID to kill on host ${hostId}:`);
    if (!processName) return;
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/rtr/kill`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ process: processName }),
      });
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
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ path: filePath }),
      });
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

  const handleContainHost = async (hostId) => {
    if (!window.confirm(`Are you sure you want to network contain this host? This will isolate it from the network.`)) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/contain`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
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
    if (!window.confirm(`Are you sure you want to lift containment on this host?`)) {
      return;
    }
    try {
      const res = await fetch(`${API_BASE}/hosts/${hostId}/lift-containment`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
      });
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

  if (!isAuthenticated) {
    return (
      <div className="min-h-screen bg-gradient-to-br from-gray-900 to-gray-800 flex items-center justify-center p-4">
        <div className="bg-white rounded-lg shadow-2xl p-8 max-w-md w-full">
          <div className="flex items-center justify-center mb-6">
            <Shield className="w-12 h-12 text-red-600 mr-3" />
            <h1 className="text-3xl font-bold text-gray-800">Falcon Manager</h1>
          </div>
          <p className="text-gray-600 text-center mb-6">Enterprise Security Operations Platform</p>
          <div className="space-y-4">
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">API Base URL</label>
              <input
                type="text"
                value={credentials.baseUrl}
                onChange={(e) => setCredentials({ ...credentials, baseUrl: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Client ID</label>
              <input
                type="text"
                value={credentials.clientId}
                onChange={(e) => setCredentials({ ...credentials, clientId: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-700 mb-2">Client Secret</label>
              <input
                type="password"
                value={credentials.clientSecret}
                onChange={(e) => setCredentials({ ...credentials, clientSecret: e.target.value })}
                className="w-full px-4 py-2 border border-gray-300 rounded-lg focus:ring-2 focus:ring-red-500 focus:border-transparent"
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

  return (
    <div className="min-h-screen bg-gray-50">
      <header className="bg-white shadow-sm border-b border-gray-200">
        <div className="px-6 py-4">
          <div className="flex items-center justify-between">
            <div className="flex items-center space-x-4">
              <Shield className="w-8 h-8 text-red-600" />
              <h1 className="text-2xl font-bold text-gray-800">Falcon Manager Pro</h1>
              <div className="flex items-center px-3 py-1 bg-green-100 rounded-full">
                <Activity className="w-4 h-4 text-green-600 mr-2" />
                <span className="text-sm text-green-700">Auto-refresh</span>
              </div>
            </div>
            <div className="flex items-center space-x-3">
              <button onClick={() => setShowHashDialog(true)} className="flex items-center px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700">
                <AlertCircle className="w-4 h-4 mr-2" />Close by Hash
              </button>
              <button onClick={handleHashAnalysis} className="flex items-center px-4 py-2 bg-teal-600 text-white rounded-lg hover:bg-teal-700">
                <Activity className="w-4 h-4 mr-2" />Hash Analysis
              </button>
              <button onClick={() => setShowAdvancedSearchDialog(true)} className="flex items-center px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">
                <Search className="w-4 h-4 mr-2" />Advanced Search
              </button>
              <button onClick={() => handleGenerateReport('detections')} className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                <Download className="w-4 h-4 mr-2" />Report
              </button>
              <button onClick={() => setShowViewDialog(true)} className="flex items-center px-4 py-2 bg-blue-600 text-white rounded-lg hover:bg-blue-700">
                <Save className="w-4 h-4 mr-2" />Save View
              </button>
              <button onClick={fetchAllData} className="flex items-center px-4 py-2 bg-gray-100 text-gray-700 rounded-lg hover:bg-gray-200">
                <RefreshCw className="w-4 h-4 mr-2" />Refresh
              </button>
            </div>
          </div>
        </div>
      </header>

      <div className="px-6 py-6">
        <div className="grid grid-cols-1 md:grid-cols-5 gap-4 mb-6">
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Active Detections</p>
                <p className="text-3xl font-bold text-gray-800">{detections.filter((d) => d.status !== 'resolved').length}</p>
              </div>
              <AlertTriangle className="w-10 h-10 text-red-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Total Hosts</p>
                <p className="text-3xl font-bold text-gray-800">{hosts.length}</p>
              </div>
              <Server className="w-10 h-10 text-blue-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Custom IOCs</p>
                <p className="text-3xl font-bold text-gray-800">{iocs.length}</p>
              </div>
              <AlertCircle className="w-10 h-10 text-orange-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Playbooks</p>
                <p className="text-3xl font-bold text-gray-800">{playbooks.length}</p>
              </div>
              <Play className="w-10 h-10 text-purple-500" />
            </div>
          </div>
          <div className="bg-white rounded-lg shadow p-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-gray-600">Saved Views</p>
                <p className="text-3xl font-bold text-gray-800">{savedViews.length}</p>
              </div>
              <Eye className="w-10 h-10 text-green-500" />
            </div>
          </div>
        </div>

        <div className="bg-white rounded-lg shadow mb-6">
          <div className="border-b border-gray-200">
            <nav className="flex space-x-8 px-6">
              {[
                { id: 'dashboard', name: 'Dashboard', icon: Activity },
                { id: 'detections', name: 'Detections', icon: AlertTriangle },
                { id: 'hosts', name: 'Hosts', icon: Server },
                { id: 'iocs', name: 'IOC Management', icon: AlertCircle },
                { id: 'playbooks', name: 'Playbooks', icon: Play },
                { id: 'views', name: 'Saved Views', icon: Eye },
              ].map((tab) => (
                <button
                  key={tab.id}
                  onClick={() => setActiveTab(tab.id)}
                  className={`flex items-center py-4 px-1 border-b-2 font-medium text-sm ${
                    activeTab === tab.id ? 'border-red-600 text-red-600' : 'border-transparent text-gray-500 hover:text-gray-700'
                  }`}
                >
                  <tab.icon className="w-5 h-5 mr-2" />
                  {tab.name}
                </button>
              ))}
            </nav>
          </div>

          {activeTab === 'dashboard' && (
            <div className="p-6">
              <div className="flex justify-between items-center mb-6">
                <h2 className="text-2xl font-bold text-gray-800">Security Analytics Dashboard</h2>
                <div className="flex items-center space-x-2 px-4 py-2 bg-blue-50 border border-blue-200 rounded-lg">
                  <Activity className="w-4 h-4 text-blue-600" />
                  <span className="text-sm font-medium text-blue-800">Last 24 Hours</span>
                </div>
              </div>

              {dashboardStats ? (
                <>
                  <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
                    <div className="bg-gradient-to-br from-red-50 to-red-100 rounded-lg shadow p-6 border border-red-200">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-semibold text-red-900">Critical</h3>
                        <AlertTriangle className="w-6 h-6 text-red-600" />
                      </div>
                      <p className="text-3xl font-bold text-red-700">{dashboardStats.severityCounts.critical}</p>
                      <p className="text-xs text-red-600 mt-1">Immediate attention required</p>
                    </div>
                    
                    <div className="bg-gradient-to-br from-orange-50 to-orange-100 rounded-lg shadow p-6 border border-orange-200">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-semibold text-orange-900">High</h3>
                        <AlertCircle className="w-6 h-6 text-orange-600" />
                      </div>
                      <p className="text-3xl font-bold text-orange-700">{dashboardStats.severityCounts.high}</p>
                      <p className="text-xs text-orange-600 mt-1">High priority threats</p>
                    </div>
                    
                    <div className="bg-gradient-to-br from-yellow-50 to-yellow-100 rounded-lg shadow p-6 border border-yellow-200">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-semibold text-yellow-900">Medium</h3>
                        <Activity className="w-6 h-6 text-yellow-600" />
                      </div>
                      <p className="text-3xl font-bold text-yellow-700">{dashboardStats.severityCounts.medium}</p>
                      <p className="text-xs text-yellow-600 mt-1">Monitor and investigate</p>
                    </div>
                    
                    <div className="bg-gradient-to-br from-blue-50 to-blue-100 rounded-lg shadow p-6 border border-blue-200">
                      <div className="flex items-center justify-between mb-2">
                        <h3 className="text-sm font-semibold text-blue-900">Low</h3>
                        <Shield className="w-6 h-6 text-blue-600" />
                      </div>
                      <p className="text-3xl font-bold text-blue-700">{dashboardStats.severityCounts.low}</p>
                      <p className="text-xs text-blue-600 mt-1">Low risk detections</p>
                    </div>
                  </div>

                  <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 mb-6">
                    <div className="bg-white rounded-lg shadow p-6">
                      <h3 className="text-lg font-bold text-gray-800 mb-4">Detection Timeline (24 Hours)</h3>
                      <div className="h-64 flex items-end space-x-1 overflow-x-auto pb-8">
                        {dashboardStats.timelineData.map((bucket, idx) => {
                          const maxHeight = Math.max(...dashboardStats.timelineData.map(b => b.total));
                          const height = maxHeight > 0 ? (bucket.total / maxHeight) * 100 : 0;
                          
                          return (
                            <div key={idx} className="flex-shrink-0 flex flex-col items-center" style={{ width: '32px' }}>
                              <div className="w-full flex flex-col justify-end" style={{ height: '200px' }}>
                                {bucket.critical > 0 && (
                                  <div 
                                    className="w-full bg-red-500 hover:bg-red-600 transition-colors cursor-pointer"
                                    style={{ height: `${(bucket.critical / bucket.total) * height * 2}px` }}
                                    title={`${bucket.hour}:00 - Critical: ${bucket.critical}`}
                                  />
                                )}
                                {bucket.high > 0 && (
                                  <div 
                                    className="w-full bg-orange-500 hover:bg-orange-600 transition-colors cursor-pointer"
                                    style={{ height: `${(bucket.high / bucket.total) * height * 2}px` }}
                                    title={`${bucket.hour}:00 - High: ${bucket.high}`}
                                  />
                                )}
                                {bucket.medium > 0 && (
                                  <div 
                                    className="w-full bg-yellow-500 hover:bg-yellow-600 transition-colors cursor-pointer"
                                    style={{ height: `${(bucket.medium / bucket.total) * height * 2}px` }}
                                    title={`${bucket.hour}:00 - Medium: ${bucket.medium}`}
                                  />
                                )}
                                {bucket.low > 0 && (
                                  <div 
                                    className="w-full bg-blue-500 hover:bg-blue-600 transition-colors cursor-pointer"
                                    style={{ height: `${(bucket.low / bucket.total) * height * 2}px` }}
                                    title={`${bucket.hour}:00 - Low: ${bucket.low}`}
                                  />
                                )}
                                {bucket.unknown > 0 && (
                                  <div 
                                    className="w-full bg-gray-500 hover:bg-gray-600 transition-colors cursor-pointer"
                                    style={{ height: `${(bucket.unknown / bucket.total) * height * 2}px` }}
                                    title={`${bucket.hour}:00 - Unknown: ${bucket.unknown}`}
                                  />
                                )}
                              </div>
                              <span className="text-xs text-gray-500 mt-2 whitespace-nowrap">
                                {bucket.hour}:00
                              </span>
                            </div>
                          );
                        })}
                      </div>
                      <div className="flex justify-center space-x-4 mt-4 text-xs flex-wrap">
                        <div className="flex items-center"><div className="w-3 h-3 bg-red-500 rounded mr-1"></div> Critical</div>
                        <div className="flex items-center"><div className="w-3 h-3 bg-orange-500 rounded mr-1"></div> High</div>
                        <div className="flex items-center"><div className="w-3 h-3 bg-yellow-500 rounded mr-1"></div> Medium</div>
                        <div className="flex items-center"><div className="w-3 h-3 bg-blue-500 rounded mr-1"></div> Low</div>
                        <div className="flex items-center"><div className="w-3 h-3 bg-gray-500 rounded mr-1"></div> Unknown</div>
                      </div>
                    </div>

                    <div className="bg-white rounded-lg shadow p-6">
                      <h3 className="text-lg font-bold text-gray-800 mb-4">Detection Status Breakdown</h3>
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
                                <span className="font-medium text-gray-700 capitalize">{status.replace('_', ' ')}</span>
                                <span className="text-gray-600">{count} ({percentage}%)</span>
                              </div>
                              <div className="w-full bg-gray-200 rounded-full h-2">
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

                  <div className="bg-white rounded-lg shadow p-6">
                    <h3 className="text-lg font-bold text-gray-800 mb-4">Summary Statistics</h3>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <p className="text-2xl font-bold text-gray-800">{dashboardStats.totalDetections}</p>
                        <p className="text-sm text-gray-600">Total Detections</p>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <p className="text-2xl font-bold text-gray-800">
                          {dashboardStats.severityCounts.critical + dashboardStats.severityCounts.high}
                        </p>
                        <p className="text-sm text-gray-600">High Priority</p>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <p className="text-2xl font-bold text-gray-800">
                          {((dashboardStats.statusCounts.closed + dashboardStats.statusCounts.false_positive) / Math.max(dashboardStats.totalDetections, 1) * 100).toFixed(1)}%
                        </p>
                        <p className="text-sm text-gray-600">Resolution Rate</p>
                      </div>
                      <div className="text-center p-4 bg-gray-50 rounded-lg">
                        <p className="text-2xl font-bold text-gray-800">{dashboardStats.statusCounts.new}</p>
                        <p className="text-sm text-gray-600">Pending Review</p>
                      </div>
                    </div>
                  </div>
                </>
              ) : (
                <div className="flex items-center justify-center h-64">
                  <div className="text-center">
                    <Activity className="w-12 h-12 text-gray-400 mx-auto mb-4 animate-pulse" />
                    <p className="text-gray-600">Loading dashboard data...</p>
                  </div>
                </div>
              )}
            </div>
          )}

          {activeTab === 'detections' && (
            <div className="p-6">
              <div className="flex items-center justify-between mb-4">
                <div className="flex items-center space-x-4 flex-1">
                  <input
                    type="text"
                    placeholder="Search detections..."
                    value={searchQuery}
                    onChange={(e) => setSearchQuery(e.target.value)}
                    className="flex-1 px-4 py-2 border rounded-lg"
                  />
                  <select
                    value={selectedSeverity}
                    onChange={(e) => setSelectedSeverity(e.target.value)}
                    className="px-4 py-2 border rounded-lg"
                  >
                    <option value="all">All Severities</option>
                    <option value="critical">Critical</option>
                    <option value="high">High</option>
                    <option value="medium">Medium</option>
                    <option value="low">Low</option>
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
              
              <div className="flex items-center mb-3 pb-2 border-b">
                <input
                  type="checkbox"
                  checked={selectedDetections.length === detections.filter((d) => selectedSeverity === 'all' || d.severity === selectedSeverity).filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase())).length && detections.filter((d) => selectedSeverity === 'all' || d.severity === selectedSeverity).filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase())).length > 0}
                  onChange={(e) => {
                    const visibleDetections = detections
                      .filter((d) => selectedSeverity === 'all' || d.severity === selectedSeverity)
                      .filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase()));
                    if (e.target.checked) {
                      setSelectedDetections(visibleDetections.map(d => d.id));
                    } else {
                      setSelectedDetections([]);
                    }
                  }}
                  className="mr-3"
                />
                <span className="text-sm font-medium text-gray-700">
                  Select All ({detections.filter((d) => selectedSeverity === 'all' || d.severity === selectedSeverity).filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase())).length} detections)
                </span>
              </div>
              
              <div className="space-y-4">
                {detections
                  .filter((d) => selectedSeverity === 'all' || d.severity === selectedSeverity)
                  .filter((d) => d.name.toLowerCase().includes(searchQuery.toLowerCase()))
                  .map((detection) => (
                    <div key={detection.id} className="border rounded-lg p-4 hover:shadow-md transition-shadow">
                      <div className="flex items-start">
                        <input
                          type="checkbox"
                          checked={selectedDetections.includes(detection.id)}
                          onChange={() => toggleDetectionSelection(detection.id)}
                          className="mt-1 mr-4"
                        />
                        <div className="flex-1">
                          <div className="flex items-center space-x-3 mb-2">
                            <span className={`px-3 py-1 rounded-full text-xs font-semibold uppercase ${getSeverityColor(detection.severity || 'unknown')}`}>
                              {detection.severity || 'unknown'}
                            </span>
                            <span className="text-sm text-gray-600 capitalize">{detection.status || 'new'}</span>
                            <span className="text-sm text-gray-500">Assigned: {detection.assigned_to || 'Unassigned'}</span>
                          </div>
                          <h3 className="text-lg font-semibold text-gray-800 mb-1">{detection.name || 'Unknown'}</h3>
                          <div className="flex items-center space-x-4 text-sm text-gray-600">
                            <span>Host: <span className="font-medium">{detection.host || 'Unknown'}</span></span>
                            <span>Behavior: {detection.behavior || 'Unknown'}</span>
                            <span>{detection.timestamp ? new Date(detection.timestamp).toLocaleString() : 'N/A'}</span>
                          </div>
                        </div>
                        <div className="flex space-x-2">
                          <button onClick={() => openCommentDialog(detection.id, 'resolve')} className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 text-sm">
                            Resolve
                          </button>
                          <button onClick={() => openCommentDialog(detection.id, 'close_fp')} className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 text-sm">
                            Close (FP)
                          </button>
                          <button onClick={() => openCommentDialog(detection.id, 'ignore')} className="px-4 py-2 bg-gray-200 text-gray-700 rounded-lg hover:bg-gray-300 text-sm">
                            Ignore
                          </button>
                        </div>
                      </div>
                    </div>
                  ))}
              </div>
            </div>
          )}

          {activeTab === 'hosts' && (
            <div className="p-6">
              <h2 className="text-xl font-bold mb-4">Managed Hosts</h2>
              <div className="space-y-4">
                {hosts.map((host) => (
                  <div key={host.id} className="border rounded-lg p-4">
                    <div className="flex justify-between">
                      <div>
                        <h3 className="font-semibold text-lg">{host.hostname}</h3>
                        <p className="text-sm text-gray-600">IP: {host.ip}</p>
                        <p className="text-sm text-gray-600">OS: {host.os}</p>
                      </div>
                      <div className="flex items-center">
                        <span className={`px-3 py-1 rounded-full text-xs ${host.status === 'online' ? 'bg-green-100 text-green-800' : 'bg-gray-100 text-gray-800'}`}>
                          {host.status}
                        </span>
                      </div>
                    </div>
                    <div className="flex space-x-2 mt-4">
                      <button onClick={() => handleContainHost(host.id)} className="px-3 py-2 text-xs bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                        Network Contain
                      </button>
                      <button onClick={() => handleLiftContainment(host.id)} className="px-3 py-2 text-xs bg-green-600 text-white rounded-lg hover:bg-green-700">
                        Lift Containment
                      </button>
                      <button onClick={() => handleKillProcess(host.id)} className="px-3 py-2 text-xs bg-red-600 text-white rounded-lg hover:bg-red-700">
                        Kill Process (RTR)
                      </button>
                      <button onClick={() => handleDeleteFile(host.id)} className="px-3 py-2 text-xs bg-orange-600 text-white rounded-lg hover:bg-orange-700">
                        Delete File (RTR)
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'iocs' && (
            <div className="p-6">
              <div className="flex justify-between mb-4">
                <h2 className="text-xl font-bold">Custom IOC Management</h2>
                <button onClick={() => setShowIOCDialog(true)} className="flex items-center px-4 py-2 bg-red-600 text-white rounded-lg hover:bg-red-700">
                  <Plus className="w-4 h-4 mr-2" />Add IOC
                </button>
              </div>
              <div className="space-y-4">
                {iocs.map((ioc) => (
                  <div key={ioc.id} className="border rounded-lg p-4">
                    <div className="flex justify-between">
                      <div>
                        <span className="font-semibold">{ioc.type}</span>: {ioc.value}
                        <p className="text-sm text-gray-600">{ioc.description}</p>
                      </div>
                      <span className={`px-3 py-1 rounded-full text-xs ${getSeverityColor(ioc.severity)}`}>{ioc.severity}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'playbooks' && (
            <div className="p-6">
              <div className="flex justify-between mb-4">
                <h2 className="text-xl font-bold">Automated Response Playbooks</h2>
                <button onClick={() => setShowPlaybookDialog(true)} className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                  <Plus className="w-4 h-4 mr-2" />Create Playbook
                </button>
              </div>
              <div className="space-y-4">
                {playbooks.map((playbook) => (
                  <div key={playbook.id} className="border rounded-lg p-4">
                    <div className="flex justify-between items-start">
                      <div>
                        <h3 className="font-semibold text-lg">{playbook.name}</h3>
                        <p className="text-sm text-gray-600">Trigger: {playbook.trigger}</p>
                        <p className="text-sm text-gray-600">Actions: {playbook.actions.length}</p>
                      </div>
                      <button onClick={() => handleExecutePlaybook(playbook.id, detections[0]?.id)} className="flex items-center px-4 py-2 bg-purple-600 text-white rounded-lg hover:bg-purple-700">
                        <Play className="w-4 h-4 mr-2" />Execute
                      </button>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}

          {activeTab === 'views' && (
            <div className="p-6">
              <h2 className="text-xl font-bold mb-4">Saved Dashboard Views</h2>
              <div className="grid grid-cols-2 gap-4">
                {savedViews.map((view) => (
                  <div key={view.id} className="border rounded-lg p-4 hover:shadow-md cursor-pointer">
                    <h3 className="font-semibold">{view.name}</h3>
                    <p className="text-sm text-gray-600">Created: {new Date(view.created).toLocaleDateString()}</p>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      </div>

      {showCommentDialog && <CommentDialog commentData={commentData} setCommentData={setCommentData} onConfirm={handleDetectionAction} onClose={() => setShowCommentDialog(false)} />}
      {showIOCDialog && <IOCDialog onClose={() => setShowIOCDialog(false)} onCreate={handleCreateIOC} />}
      {showPlaybookDialog && <PlaybookDialog onClose={() => setShowPlaybookDialog(false)} onCreate={handleCreatePlaybook} />}
      {showViewDialog && <ViewDialog onClose={() => setShowViewDialog(false)} onSave={handleSaveView} currentFilters={{ severity: selectedSeverity, search: searchQuery }} />}
      {showHashDialog && <CloseByHashDialog onClose={() => setShowHashDialog(false)} onSubmit={handleCloseByHash} />}
      {showHashAnalysisDialog && hashAnalysis && <HashAnalysisDialog data={hashAnalysis} onClose={() => setShowHashAnalysisDialog(false)} onCloseHash={() => { setShowHashAnalysisDialog(false); setShowHashDialog(true); }} onCreateExclusion={() => { setShowHashAnalysisDialog(false); setShowExclusionDialog(true); }} />}
      {showAdvancedSearchDialog && <AdvancedSearchDialog onClose={() => setShowAdvancedSearchDialog(false)} onSearch={handleAdvancedSearch} />}
      {showExclusionDialog && <IOCExclusionDialog onClose={() => setShowExclusionDialog(false)} onCreate={handleCreateExclusion} />}
      {notification && <div className={`fixed bottom-4 right-4 px-6 py-3 rounded-lg shadow-lg ${notification.type === 'success' ? 'bg-green-600' : 'bg-red-600'} text-white z-50`}>{notification.message}</div>}
    </div>
  );
};

const CommentDialog = ({ commentData, setCommentData, onConfirm, onClose }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white rounded-lg p-6 max-w-md w-full">
      <h3 className="text-xl font-bold mb-4">Add Comment</h3>
      <textarea value={commentData.comment} onChange={(e) => setCommentData({ ...commentData, comment: e.target.value })} className="w-full px-4 py-2 border rounded-lg mb-4" rows="4" placeholder="Enter your comment..." />
      <div className="flex justify-end space-x-2">
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
        <button onClick={onConfirm} className="px-4 py-2 bg-red-600 text-white rounded-lg">Confirm</button>
      </div>
    </div>
  </div>
);

const IOCDialog = ({ onClose, onCreate }) => {
  const [iocData, setIOCData] = useState({ type: 'ipv4', value: '', policy: 'detect', description: '', severity: 'medium', tags: [] });
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4">Create Custom IOC</h3>
        <div className="space-y-4">
          <select value={iocData.type} onChange={(e) => setIOCData({ ...iocData, type: e.target.value })} className="w-full px-4 py-2 border rounded-lg">
            <option value="ipv4">IPv4 Address</option>
            <option value="domain">Domain</option>
            <option value="md5">MD5 Hash</option>
            <option value="sha256">SHA256 Hash</option>
          </select>
          <input type="text" placeholder="IOC Value" value={iocData.value} onChange={(e) => setIOCData({ ...iocData, value: e.target.value })} className="w-full px-4 py-2 border rounded-lg" />
          <select value={iocData.severity} onChange={(e) => setIOCData({ ...iocData, severity: e.target.value })} className="w-full px-4 py-2 border rounded-lg">
            <option value="critical">Critical</option>
            <option value="high">High</option>
            <option value="medium">Medium</option>
            <option value="low">Low</option>
          </select>
          <textarea placeholder="Description" value={iocData.description} onChange={(e) => setIOCData({ ...iocData, description: e.target.value })} className="w-full px-4 py-2 border rounded-lg" rows="3" />
        </div>
        <div className="flex justify-end space-x-2 mt-4">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onCreate(iocData)} className="px-4 py-2 bg-red-600 text-white rounded-lg">Create IOC</button>
        </div>
      </div>
    </div>
  );
};

const PlaybookDialog = ({ onClose, onCreate }) => {
  const [playbookData, setPlaybookData] = useState({ name: '', trigger: 'critical_detection', actions: [{ type: 'contain_host' }], enabled: true });
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4">Create Automated Playbook</h3>
        <div className="space-y-4">
          <input type="text" placeholder="Playbook Name" value={playbookData.name} onChange={(e) => setPlaybookData({ ...playbookData, name: e.target.value })} className="w-full px-4 py-2 border rounded-lg" />
          <select value={playbookData.trigger} onChange={(e) => setPlaybookData({ ...playbookData, trigger: e.target.value })} className="w-full px-4 py-2 border rounded-lg">
            <option value="critical_detection">Critical Detection</option>
            <option value="high_detection">High Severity Detection</option>
            <option value="ransomware">Ransomware Activity</option>
          </select>
          <div className="border rounded-lg p-4">
            <h4 className="font-semibold mb-2">Actions</h4>
            <label className="flex items-center"><input type="checkbox" className="mr-2" defaultChecked />Contain Host</label>
            <label className="flex items-center"><input type="checkbox" className="mr-2" />Create Incident</label>
          </div>
        </div>
        <div className="flex justify-end space-x-2 mt-4">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onCreate(playbookData)} className="px-4 py-2 bg-purple-600 text-white rounded-lg">Create Playbook</button>
        </div>
      </div>
    </div>
  );
};

const ViewDialog = ({ onClose, onSave, currentFilters }) => {
  const [viewName, setViewName] = useState('');
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4">Save Current View</h3>
        <input type="text" placeholder="View Name" value={viewName} onChange={(e) => setViewName(e.target.value)} className="w-full px-4 py-2 border rounded-lg mb-4" />
        <p className="text-sm text-gray-600 mb-4">This will save your current filters and layout settings</p>
        <div className="flex justify-end space-x-2">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onSave({ name: viewName, filters: currentFilters })} className="px-4 py-2 bg-blue-600 text-white rounded-lg">Save View</button>
        </div>
      </div>
    </div>
  );
};

const CloseByHashDialog = ({ onClose, onSubmit }) => {
  const [hashData, setHashData] = useState({ hash: '', comment: 'Closed via hash - approved by SOC', status: 'closed', dry_run: false });
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4">Close Detections by SHA256 Hash</h3>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">SHA256 Hash</label>
            <input type="text" placeholder="Enter SHA256 hash..." value={hashData.hash} onChange={(e) => setHashData({ ...hashData, hash: e.target.value })} className="w-full px-4 py-2 border rounded-lg font-mono text-sm" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Comment</label>
            <textarea value={hashData.comment} onChange={(e) => setHashData({ ...hashData, comment: e.target.value })} className="w-full px-4 py-2 border rounded-lg" rows="3" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Status</label>
            <select value={hashData.status} onChange={(e) => setHashData({ ...hashData, status: e.target.value })} className="w-full px-4 py-2 border rounded-lg">
              <option value="closed">Closed</option>
              <option value="resolved">Resolved</option>
              <option value="in_progress">In Progress</option>
            </select>
          </div>
          <label className="flex items-center">
            <input type="checkbox" checked={hashData.dry_run} onChange={(e) => setHashData({ ...hashData, dry_run: e.target.checked })} className="mr-2" />
            <span className="text-sm">Dry run (preview only, no changes)</span>
          </label>
        </div>
        <div className="flex justify-end space-x-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onSubmit(hashData)} className="px-4 py-2 bg-orange-600 text-white rounded-lg hover:bg-orange-700">{hashData.dry_run ? 'Preview' : 'Close Detections'}</button>
        </div>
      </div>
    </div>
  );
};

const HashAnalysisDialog = ({ data, onClose, onCloseHash, onCreateExclusion }) => (
  <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
    <div className="bg-white rounded-lg p-6 max-w-4xl w-full max-h-[80vh] overflow-hidden flex flex-col">
      <h3 className="text-xl font-bold mb-4">Hash Analysis Report</h3>
      <div className="bg-gray-50 p-4 rounded-lg mb-4">
        <div className="grid grid-cols-3 gap-4 text-center">
          <div><p className="text-sm text-gray-600">Total Detections</p><p className="text-2xl font-bold">{data.total_detections}</p></div>
          <div><p className="text-sm text-gray-600">Unique Hashes</p><p className="text-2xl font-bold">{data.unique_hashes}</p></div>
          <div><p className="text-sm text-gray-600">Most Common</p><p className="text-2xl font-bold">{data.hashes[0]?.count || 0}</p></div>
        </div>
      </div>
      <div className="flex-1 overflow-auto">
        <table className="w-full">
          <thead className="bg-gray-100 sticky top-0">
            <tr>
              <th className="px-4 py-2 text-left text-sm font-semibold">Hash</th>
              <th className="px-4 py-2 text-center text-sm font-semibold">Count</th>
              <th className="px-4 py-2 text-right text-sm font-semibold">Actions</th>
            </tr>
          </thead>
          <tbody>
            {data.hashes.map((item) => (
              <tr key={item.hash} className="border-b hover:bg-gray-50">
                <td className="px-4 py-3 font-mono text-xs">{item.hash}</td>
                <td className="px-4 py-3 text-center"><span className="px-2 py-1 bg-blue-100 text-blue-800 rounded-full text-sm font-semibold">{item.count}</span></td>
                <td className="px-4 py-3 text-right">
                  <button onClick={() => onCloseHash(item.hash)} className="px-3 py-1 bg-orange-600 text-white rounded text-sm hover:bg-orange-700 mr-2">Close All</button>
                  <button onClick={() => onCreateExclusion(item.hash)} className="px-3 py-1 bg-green-600 text-white rounded text-sm hover:bg-green-700">Exclude</button>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
      <div className="flex justify-end mt-4">
        <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Close</button>
      </div>
    </div>
  </div>
);

const AdvancedSearchDialog = ({ onClose, onSearch }) => {
  const [filterString, setFilterString] = useState('');
  const examples = [
    { label: 'New detections', filter: 'status:"new"' },
    { label: 'High severity', filter: 'max_severity_displayname:"High"' },
    { label: 'Specific host', filter: 'device.hostname:"HOSTNAME"' },
    { label: 'Last 24h', filter: 'first_behavior:>"now-24h"' },
    { label: 'Custom Intelligence', filter: 'behaviors.tactic:"Custom Intelligence"' },
  ];
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-2xl w-full">
        <h3 className="text-xl font-bold mb-4">Advanced FQL Search</h3>
        <div className="mb-4">
          <label className="block text-sm font-medium mb-2">FQL Filter String</label>
          <textarea value={filterString} onChange={(e) => setFilterString(e.target.value)} className="w-full px-4 py-2 border rounded-lg font-mono text-sm" rows="4" placeholder='Example: status:"new"+max_severity_displayname:"High"' />
        </div>
        <div className="mb-4">
          <p className="text-sm font-medium mb-2">Quick Examples:</p>
          <div className="flex flex-wrap gap-2">
            {examples.map((ex) => (
              <button key={ex.label} onClick={() => setFilterString(ex.filter)} className="px-3 py-1 bg-gray-100 hover:bg-gray-200 rounded text-sm">{ex.label}</button>
            ))}
          </div>
        </div>
        <div className="flex justify-end space-x-2">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onSearch(filterString)} className="px-4 py-2 bg-indigo-600 text-white rounded-lg hover:bg-indigo-700">Search</button>
        </div>
      </div>
    </div>
  );
};

const IOCExclusionDialog = ({ onClose, onCreate }) => {
  const [exclusionData, setExclusionData] = useState({ hash: '', type: 'sha256', description: '', applied_globally: true, host_groups: [], severity: 'informational' });
  return (
    <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center z-50">
      <div className="bg-white rounded-lg p-6 max-w-md w-full">
        <h3 className="text-xl font-bold mb-4">Create IOC Exclusion</h3>
        <p className="text-sm text-gray-600 mb-4">This will prevent future detections for this hash</p>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium mb-2">Hash Type</label>
            <select value={exclusionData.type} onChange={(e) => setExclusionData({ ...exclusionData, type: e.target.value })} className="w-full px-4 py-2 border rounded-lg">
              <option value="sha256">SHA256</option>
              <option value="sha1">SHA1</option>
              <option value="md5">MD5</option>
            </select>
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Hash Value</label>
            <input type="text" placeholder="Enter hash..." value={exclusionData.hash} onChange={(e) => setExclusionData({ ...exclusionData, hash: e.target.value })} className="w-full px-4 py-2 border rounded-lg font-mono text-sm" />
          </div>
          <div>
            <label className="block text-sm font-medium mb-2">Description (Required)</label>
            <textarea value={exclusionData.description} onChange={(e) => setExclusionData({ ...exclusionData, description: e.target.value })} className="w-full px-4 py-2 border rounded-lg" rows="3" placeholder="Why is this being excluded? (e.g., Internal tool, approved software)" />
          </div>
          <label className="flex items-center">
            <input type="checkbox" checked={exclusionData.applied_globally} onChange={(e) => setExclusionData({ ...exclusionData, applied_globally: e.target.checked })} className="mr-2" />
            <span className="text-sm">Apply globally to all hosts</span>
          </label>
        </div>
        <div className="flex justify-end space-x-2 mt-6">
          <button onClick={onClose} className="px-4 py-2 bg-gray-200 rounded-lg">Cancel</button>
          <button onClick={() => onCreate(exclusionData)} disabled={!exclusionData.hash || !exclusionData.description} className="px-4 py-2 bg-green-600 text-white rounded-lg hover:bg-green-700 disabled:opacity-50">Create Exclusion</button>
        </div>
      </div>
    </div>
  );
};

export default FalconDashboard;