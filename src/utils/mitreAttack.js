// src/utils/mitreAttack.js
import { ExternalLink, Shield, AlertTriangle } from 'lucide-react';

export const MITRE_ATTACK_TACTICS = {
  'reconnaissance': { id: 'TA0043', name: 'Reconnaissance', color: '#6b7280' },
  'resource-development': { id: 'TA0042', name: 'Resource Development', color: '#6b7280' },
  'initial-access': { id: 'TA0001', name: 'Initial Access', color: '#ef4444' },
  'execution': { id: 'TA0002', name: 'Execution', color: '#f59e0b' },
  'persistence': { id: 'TA0003', name: 'Persistence', color: '#eab308' },
  'privilege-escalation': { id: 'TA0004', name: 'Privilege Escalation', color: '#f97316' },
  'defense-evasion': { id: 'TA0005', name: 'Defense Evasion', color: '#a855f7' },
  'credential-access': { id: 'TA0006', name: 'Credential Access', color: '#ec4899' },
  'discovery': { id: 'TA0007', name: 'Discovery', color: '#3b82f6' },
  'lateral-movement': { id: 'TA0008', name: 'Lateral Movement', color: '#06b6d4' },
  'collection': { id: 'TA0009', name: 'Collection', color: '#14b8a6' },
  'command-and-control': { id: 'TA0011', name: 'Command and Control', color: '#10b981' },
  'exfiltration': { id: 'TA0010', name: 'Exfiltration', color: '#84cc16' },
  'impact': { id: 'TA0040', name: 'Impact', color: '#dc2626' }
};

export const MITRE_TECHNIQUES = {
  // Initial Access
  'T1566': { id: 'T1566', name: 'Phishing', tactic: 'initial-access', description: 'Adversaries may send phishing messages to gain access' },
  'T1190': { id: 'T1190', name: 'Exploit Public-Facing Application', tactic: 'initial-access', description: 'Adversaries may attempt to exploit weakness in an Internet-facing host' },
  'T1133': { id: 'T1133', name: 'External Remote Services', tactic: 'initial-access', description: 'Adversaries may leverage external remote services to initially access' },
  
  // Execution
  'T1059': { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution', description: 'Adversaries may abuse command and script interpreters' },
  'T1203': { id: 'T1203', name: 'Exploitation for Client Execution', tactic: 'execution', description: 'Adversaries may exploit software vulnerabilities in client applications' },
  'T1204': { id: 'T1204', name: 'User Execution', tactic: 'execution', description: 'An adversary may rely upon specific actions by a user' },
  'T1053': { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'execution', description: 'Adversaries may abuse task scheduling functionality' },
  
  // Persistence
  'T1547': { id: 'T1547', name: 'Boot or Logon Autostart Execution', tactic: 'persistence', description: 'Adversaries may configure system settings to automatically execute' },
  'T1078': { id: 'T1078', name: 'Valid Accounts', tactic: 'persistence', description: 'Adversaries may obtain and abuse credentials of existing accounts' },
  'T1543': { id: 'T1543', name: 'Create or Modify System Process', tactic: 'persistence', description: 'Adversaries may create or modify system-level processes' },
  
  // Privilege Escalation
  'T1548': { id: 'T1548', name: 'Abuse Elevation Control Mechanism', tactic: 'privilege-escalation', description: 'Adversaries may circumvent mechanisms designed to control elevate privileges' },
  'T1134': { id: 'T1134', name: 'Access Token Manipulation', tactic: 'privilege-escalation', description: 'Adversaries may modify access tokens to operate under a different user' },
  'T1068': { id: 'T1068', name: 'Exploitation for Privilege Escalation', tactic: 'privilege-escalation', description: 'Adversaries may exploit software vulnerabilities to elevate privileges' },
  
  // Defense Evasion
  'T1070': { id: 'T1070', name: 'Indicator Removal', tactic: 'defense-evasion', description: 'Adversaries may delete or alter generated artifacts on a host system' },
  'T1055': { id: 'T1055', name: 'Process Injection', tactic: 'defense-evasion', description: 'Adversaries may inject code into processes to evade detection' },
  'T1027': { id: 'T1027', name: 'Obfuscated Files or Information', tactic: 'defense-evasion', description: 'Adversaries may attempt to make executable code difficult to discover' },
  'T1112': { id: 'T1112', name: 'Modify Registry', tactic: 'defense-evasion', description: 'Adversaries may interact with the Windows Registry to hide configuration' },
  'T1562': { id: 'T1562', name: 'Impair Defenses', tactic: 'defense-evasion', description: 'Adversaries may maliciously modify components to impair defenses' },
  
  // Credential Access
  'T1110': { id: 'T1110', name: 'Brute Force', tactic: 'credential-access', description: 'Adversaries may use brute force techniques to gain access' },
  'T1555': { id: 'T1555', name: 'Credentials from Password Stores', tactic: 'credential-access', description: 'Adversaries may search for common password storage locations' },
  'T1003': { id: 'T1003', name: 'OS Credential Dumping', tactic: 'credential-access', description: 'Adversaries may attempt to dump credentials to obtain account login' },
  'T1056': { id: 'T1056', name: 'Input Capture', tactic: 'credential-access', description: 'Adversaries may use methods of capturing user input' },
  
  // Discovery
  'T1087': { id: 'T1087', name: 'Account Discovery', tactic: 'discovery', description: 'Adversaries may attempt to get a listing of valid accounts' },
  'T1083': { id: 'T1083', name: 'File and Directory Discovery', tactic: 'discovery', description: 'Adversaries may enumerate files and directories' },
  'T1082': { id: 'T1082', name: 'System Information Discovery', tactic: 'discovery', description: 'An adversary may attempt to get detailed information about the system' },
  'T1057': { id: 'T1057', name: 'Process Discovery', tactic: 'discovery', description: 'Adversaries may attempt to get information about running processes' },
  'T1018': { id: 'T1018', name: 'Remote System Discovery', tactic: 'discovery', description: 'Adversaries may attempt to get a listing of other systems' },
  'T1049': { id: 'T1049', name: 'System Network Connections Discovery', tactic: 'discovery', description: 'Adversaries may attempt to get a listing of network connections' },
  
  // Lateral Movement
  'T1021': { id: 'T1021', name: 'Remote Services', tactic: 'lateral-movement', description: 'Adversaries may use valid accounts to log into a service' },
  'T1080': { id: 'T1080', name: 'Taint Shared Content', tactic: 'lateral-movement', description: 'Adversaries may deliver payloads to remote systems by adding content to shared storage' },
  'T1534': { id: 'T1534', name: 'Internal Spearphishing', tactic: 'lateral-movement', description: 'Adversaries may use internal spearphishing to gain access' },
  
  // Collection
  'T1560': { id: 'T1560', name: 'Archive Collected Data', tactic: 'collection', description: 'An adversary may compress and/or encrypt data that is collected' },
  'T1119': { id: 'T1119', name: 'Automated Collection', tactic: 'collection', description: 'Once established, adversaries may use automated techniques for collecting data' },
  'T1115': { id: 'T1115', name: 'Clipboard Data', tactic: 'collection', description: 'Adversaries may collect data stored in the clipboard' },
  'T1213': { id: 'T1213', name: 'Data from Information Repositories', tactic: 'collection', description: 'Adversaries may leverage information repositories to mine valuable information' },
  
  // Command and Control
  'T1071': { id: 'T1071', name: 'Application Layer Protocol', tactic: 'command-and-control', description: 'Adversaries may communicate using application layer protocols' },
  'T1573': { id: 'T1573', name: 'Encrypted Channel', tactic: 'command-and-control', description: 'Adversaries may employ a known encryption algorithm' },
  'T1095': { id: 'T1095', name: 'Non-Application Layer Protocol', tactic: 'command-and-control', description: 'Adversaries may use non-application layer protocol for communication' },
  'T1572': { id: 'T1572', name: 'Protocol Tunneling', tactic: 'command-and-control', description: 'Adversaries may tunnel network communications' },
  
  // Exfiltration
  'T1020': { id: 'T1020', name: 'Automated Exfiltration', tactic: 'exfiltration', description: 'Adversaries may exfiltrate data using automated processing' },
  'T1030': { id: 'T1030', name: 'Data Transfer Size Limits', tactic: 'exfiltration', description: 'An adversary may exfiltrate data in fixed size chunks' },
  'T1048': { id: 'T1048', name: 'Exfiltration Over Alternative Protocol', tactic: 'exfiltration', description: 'Adversaries may steal data by exfiltrating it over a different protocol' },
  
  // Impact
  'T1486': { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact', description: 'Adversaries may encrypt data to interrupt availability (RANSOMWARE)' },
  'T1490': { id: 'T1490', name: 'Inhibit System Recovery', tactic: 'impact', description: 'Adversaries may delete or remove built-in data and backup' },
  'T1489': { id: 'T1489', name: 'Service Stop', tactic: 'impact', description: 'Adversaries may stop or disable services on a system' },
  'T1529': { id: 'T1529', name: 'System Shutdown/Reboot', tactic: 'impact', description: 'Adversaries may shutdown/reboot systems to interrupt availability' },
  'T1496': { id: 'T1496', name: 'Resource Hijacking', tactic: 'impact', description: 'Adversaries may leverage resources to solve resource intensive problems' }
};

// Map common CrowdStrike tactic/technique names to MITRE ATT&CK IDs
export const mapToMitreAttack = (detection) => {
  if (!detection) return { tactics: [], techniques: [] };

  const tactics = new Set();
  const techniques = new Set();

  // ✅ 1) Use explicit MITRE fields when present (best quality)
  // From backend: mitre_techniques like ["T1110.003"], technique_id, etc
  const explicitTechniqueIds = new Set();

  if (Array.isArray(detection.mitre_techniques)) {
    detection.mitre_techniques.forEach((id) => {
      if (typeof id === 'string') explicitTechniqueIds.add(id);
    });
  }

  if (typeof detection.technique_id === 'string') {
    explicitTechniqueIds.add(detection.technique_id);
  }

  if (Array.isArray(detection.technique_ids)) {
    detection.technique_ids.forEach((id) => {
      if (typeof id === 'string') explicitTechniqueIds.add(id);
    });
  }

  // Normalize subtechniques TXXXX.XXX -> TXXXX for our MITRE_TECHNIQUES map
  explicitTechniqueIds.forEach((rawId) => {
    let id = rawId;

    if (/^T\d{4}\.\d{3}$/.test(id)) {
      const parentId = id.split('.')[0];
      if (MITRE_TECHNIQUES[parentId]) {
        id = parentId;
      }
    }

    if (MITRE_TECHNIQUES[id]) {
      techniques.add(id);
      const techData = MITRE_TECHNIQUES[id];
      if (techData.tactic && MITRE_ATTACK_TACTICS[techData.tactic]) {
        tactics.add(techData.tactic);
      }
    }
  });

  // If explicit mapping worked, we're done ✅
  if (techniques.size > 0) {
    return {
      tactics: Array.from(tactics),
      techniques: Array.from(techniques),
    };
  }

  // ✅ 2) Fallback: keyword/ID scanning in text (existing logic)
  const allText = [
    (detection.tactic || ''),
    (detection.technique || ''),
    (detection.scenario || ''),
    (detection.description || ''),
    (detection.name || ''),
    (detection.behavior || '')
  ].join(' ').toLowerCase();
  
  // Keyword-based mapping (simple heuristic approach)
  const mappings = {
    // Ransomware indicators
    'ransomware|ransom|encrypt|crypto|wannacry|ryuk|lockbit': ['T1486'],
    
    // Execution
    'powershell|cmd|script|command': ['T1059'],
    'scheduled task|cron|at command': ['T1053'],
    
    // Persistence
    'registry|autorun|startup': ['T1547'],
    'service|systemd': ['T1543'],
    
    // Privilege Escalation
    'uac|bypass|elevate': ['T1548'],
    'token|impersonat': ['T1134'],
    
    // Defense Evasion
    'inject|hollowing': ['T1055'],
    'obfuscat|encode|pack': ['T1027'],
    'delete.*log|clear.*event': ['T1070'],
    'disable.*security|tamper': ['T1562'],
    
    // Credential Access
    'mimikatz|credential|password|dump': ['T1003'],
    'keylog': ['T1056'],
    'brute.*force': ['T1110'],
    
    // Discovery
    'whoami|net user|query': ['T1087'],
    'dir |ls |find.*file': ['T1083'],
    'systeminfo|uname': ['T1082'],
    'tasklist|ps |process': ['T1057'],
    'ipconfig|ifconfig|netstat': ['T1049'],
    'net view|arp': ['T1018'],
    
    // Lateral Movement
    'psexec|wmi|remote': ['T1021'],
    'rdp|ssh|remote desktop': ['T1021'],
    
    // Collection
    'compress|zip|rar|7z': ['T1560'],
    'clipboard': ['T1115'],
    
    // Command and Control
    'beacon|c2|c&c|callback': ['T1071'],
    'dns.*tunnel|http.*tunnel': ['T1071', 'T1572'],
    'tor |proxy': ['T1090'],
    
    // Impact
    'bcdedit|bootloader|recovery': ['T1490'],
    'vssadmin|shadow.*copy': ['T1490'],
    'stop.*service|disable.*service': ['T1489'],
    'shutdown|reboot': ['T1529'],
    'cryptominer|mining': ['T1496']
  };
  
  // Match patterns
  for (const [pattern, techniqueIds] of Object.entries(mappings)) {
  const regex = new RegExp(pattern, 'i');
  if (regex.test(allText)) {
    techniqueIds.forEach(tid => {
      if (!techniques.has(tid) && MITRE_TECHNIQUES[tid]) {  // ✅ Changed .includes to .has
        techniques.add(tid);  // ✅ Changed .push to .add
        const tacticKey = MITRE_TECHNIQUES[tid].tactic;
        if (!tactics.has(tacticKey)) {  // ✅ Changed .includes to .has
          tactics.add(tacticKey);  // ✅ Changed .push to .add
        }
      }
    });
  }
}

return { tactics: Array.from(tactics), techniques: Array.from(techniques) };
};

export const getMitreTechniqueUrl = (techniqueId) => {
  return `https://attack.mitre.org/techniques/${techniqueId}/`;
};

export const getMitreTacticUrl = (tacticId) => {
  return `https://attack.mitre.org/tactics/${tacticId}/`;
};

// React Components for MITRE ATT&CK Visualization

export const MitreTechniqueBadge = ({ techniqueId, size = 'md' }) => {
  const technique = MITRE_TECHNIQUES[techniqueId];
  if (!technique) return null;
  
  const tactic = MITRE_ATTACK_TACTICS[technique.tactic];
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-3 py-1',
    lg: 'text-base px-4 py-2'
  };
  
  return (
    <a
      href={getMitreTechniqueUrl(techniqueId)}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center ${sizeClasses[size]} rounded font-medium hover:opacity-80 transition-opacity`}
      style={{ backgroundColor: tactic.color + '20', color: tactic.color }}
      title={technique.description}
    >
      <Shield className="w-3 h-3 mr-1" />
      {techniqueId}: {technique.name}
      <ExternalLink className="w-3 h-3 ml-1" />
    </a>
  );
};

export const MitreTacticBadge = ({ tacticKey, size = 'sm' }) => {
  const tactic = MITRE_ATTACK_TACTICS[tacticKey];
  if (!tactic) return null;
  
  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-3 py-1'
  };
  
  return (
    <a
      href={getMitreTacticUrl(tactic.id)}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center ${sizeClasses[size]} rounded-full font-medium hover:opacity-80`}
      style={{ backgroundColor: tactic.color, color: 'white' }}
      title={`MITRE ATT&CK Tactic: ${tactic.name}`}
    >
      {tactic.name}
      <ExternalLink className="w-3 h-3 ml-1" />
    </a>
  );
};

export const MitreAttackMatrix = ({ detections }) => {
  // Calculate coverage statistics
  const coverageStats = {};
  const techniqueFrequency = {};
  
  detections.forEach(detection => {
    const { tactics, techniques } = mapToMitreAttack(detection);
    
    tactics.forEach(tacticKey => {
      coverageStats[tacticKey] = (coverageStats[tacticKey] || 0) + 1;
    });
    
    techniques.forEach(techniqueId => {
      techniqueFrequency[techniqueId] = (techniqueFrequency[techniqueId] || 0) + 1;
    });
  });
  
  const maxFrequency = Math.max(...Object.values(techniqueFrequency), 1);
  
  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-6">
        <div>
          <h3 className="text-xl font-bold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h3>
          <p className="text-sm text-gray-600 dark:text-gray-400">
            Based on {detections.length} detections
          </p>
        </div>
        <a
          href="https://attack.mitre.org/"
          target="_blank"
          rel="noopener noreferrer"
          className="flex items-center text-sm text-blue-600 dark:text-blue-400 hover:underline"
        >
          <Shield className="w-4 h-4 mr-1" />
          View Full Matrix
          <ExternalLink className="w-3 h-3 ml-1" />
        </a>
      </div>
      
      {/* Tactics Overview */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        {Object.entries(MITRE_ATTACK_TACTICS).map(([key, tactic]) => {
          const count = coverageStats[key] || 0;
          const opacity = count > 0 ? Math.min(0.3 + (count / detections.length) * 0.7, 1) : 0.1;
          
          return (
            <div
              key={key}
              className="rounded-lg p-3 text-center border-2 transition-all hover:scale-105"
              style={{
                backgroundColor: tactic.color + Math.floor(opacity * 255).toString(16).padStart(2, '0'),
                borderColor: count > 0 ? tactic.color : '#e5e7eb'
              }}
            >
              <div className="text-xs font-semibold mb-1" style={{ color: tactic.color }}>
                {tactic.name}
              </div>
              <div className="text-2xl font-bold text-gray-900 dark:text-white">
                {count}
              </div>
            </div>
          );
        })}
      </div>
      
      {/* Top Techniques */}
      <div>
        <h4 className="text-lg font-semibold text-gray-900 dark:text-white mb-3">
          Most Frequent Techniques
        </h4>
        <div className="space-y-2">
          {Object.entries(techniqueFrequency)
            .sort((a, b) => b[1] - a[1])
            .slice(0, 10)
            .map(([techniqueId, count]) => {
              const technique = MITRE_TECHNIQUES[techniqueId];
              const tactic = MITRE_ATTACK_TACTICS[technique.tactic];
              const percentage = (count / maxFrequency) * 100;
              
              return (
                <div key={techniqueId} className="space-y-1">
                  <div className="flex items-center justify-between text-sm">
                    <a
                      href={getMitreTechniqueUrl(techniqueId)}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="flex items-center text-gray-700 dark:text-gray-300 hover:text-blue-600 dark:hover:text-blue-400 font-medium"
                    >
                      {techniqueId}: {technique.name}
                      <ExternalLink className="w-3 h-3 ml-1" />
                    </a>
                    <span className="text-gray-600 dark:text-gray-400 font-semibold">
                      {count} detection{count !== 1 ? 's' : ''}
                    </span>
                  </div>
                  <div className="w-full bg-gray-200 dark:bg-gray-700 rounded-full h-2">
                    <div
                      className="h-2 rounded-full transition-all duration-500"
                      style={{
                        width: `${percentage}%`,
                        backgroundColor: tactic.color
                      }}
                    />
                  </div>
                </div>
              );
            })}
        </div>
      </div>
      
      {Object.keys(techniqueFrequency).length === 0 && (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          <AlertTriangle className="w-12 h-12 mx-auto mb-3 opacity-50" />
          <p>No MITRE ATT&CK techniques mapped yet</p>
          <p className="text-sm mt-1">Techniques will appear as detections are analyzed</p>
        </div>
      )}
    </div>
  );
};