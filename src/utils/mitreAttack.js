// src/utils/mitreAttack.js
import { ExternalLink, Shield, AlertTriangle } from 'lucide-react';

/* ============================================================
   MITRE ATT&CK TACTICS
============================================================ */
export const MITRE_ATTACK_TACTICS = {
  reconnaissance: { id: 'TA0043', name: 'Reconnaissance', color: '#9333ea', textColor: '#ffffff' },
  'resource-development': { id: 'TA0042', name: 'Resource Development', color: '#7c3aed', textColor: '#ffffff' },
  'initial-access': { id: 'TA0001', name: 'Initial Access', color: '#dc2626', textColor: '#ffffff' },
  execution: { id: 'TA0002', name: 'Execution', color: '#ea580c', textColor: '#ffffff' },
  persistence: { id: 'TA0003', name: 'Persistence', color: '#ca8a04', textColor: '#ffffff' },
  'privilege-escalation': { id: 'TA0004', name: 'Privilege Escalation', color: '#d97706', textColor: '#ffffff' },
  'defense-evasion': { id: 'TA0005', name: 'Defense Evasion', color: '#65a30d', textColor: '#ffffff' },
  'credential-access': { id: 'TA0006', name: 'Credential Access', color: '#059669', textColor: '#ffffff' },
  discovery: { id: 'TA0007', name: 'Discovery', color: '#0891b2', textColor: '#ffffff' },
  'lateral-movement': { id: 'TA0008', name: 'Lateral Movement', color: '#0284c7', textColor: '#ffffff' },
  collection: { id: 'TA0009', name: 'Collection', color: '#2563eb', textColor: '#ffffff' },
  'command-and-control': { id: 'TA0011', name: 'Command and Control', color: '#4f46e5', textColor: '#ffffff' },
  exfiltration: { id: 'TA0010', name: 'Exfiltration', color: '#7c3aed', textColor: '#ffffff' },
  impact: { id: 'TA0040', name: 'Impact', color: '#be123c', textColor: '#ffffff' }
};

/* ============================================================
   MITRE TECHNIQUES (LOCAL CATALOG – PARTIAL ON PURPOSE)
   NOTE: Unknown techniques are STILL counted
============================================================ */
export const MITRE_TECHNIQUES = {
  T1078: { id: 'T1078', name: 'Valid Accounts', tactic: 'persistence' },
  T1059: { id: 'T1059', name: 'Command and Scripting Interpreter', tactic: 'execution' },
  T1053: { id: 'T1053', name: 'Scheduled Task/Job', tactic: 'execution' },
  T1486: { id: 'T1486', name: 'Data Encrypted for Impact', tactic: 'impact' },
  T1110: { id: 'T1110', name: 'Brute Force', tactic: 'credential-access' }
};

/* ============================================================
   URL HELPERS (exported)
============================================================ */
export const getMitreTechniqueUrl = (techniqueId) => `https://attack.mitre.org/techniques/${techniqueId}/`;
export const getMitreTacticUrl = (tacticId) => `https://attack.mitre.org/tactics/${tacticId}/`;

/* ============================================================
   NORMALIZERS
============================================================ */
const normalizeTechniqueId = (raw) => {
  if (typeof raw !== 'string') return null;
  const id = raw.trim();
  if (/^T\d{4}\.\d{3}$/.test(id)) return id.split('.')[0];
  if (/^T\d{4}$/.test(id)) return id;
  return null;
};

const normalizeTacticKey = (raw) => {
  if (!raw || typeof raw !== 'string') return null;
  const s = raw.trim().toLowerCase();

  // already a key?
  if (MITRE_ATTACK_TACTICS[s]) return s;

  const map = {
    reconnaissance: 'reconnaissance',
    'resource development': 'resource-development',
    'initial access': 'initial-access',
    execution: 'execution',
    persistence: 'persistence',
    'privilege escalation': 'privilege-escalation',
    'defense evasion': 'defense-evasion',
    'credential access': 'credential-access',
    discovery: 'discovery',
    'lateral movement': 'lateral-movement',
    collection: 'collection',
    'command and control': 'command-and-control',
    exfiltration: 'exfiltration',
    impact: 'impact'
  };

  return map[s] || null;
};

/* ============================================================
   CORE MITRE MAPPER (CS RAW AWARE)
============================================================ */
export const mapToMitreAttack = (detection) => {
  const tactics = new Set();
  const techniques = new Set();

  const csRaw = detection?.raw_data?.cs_raw;

  // Primary: CrowdStrike mitre_attack[]
  if (Array.isArray(csRaw?.mitre_attack)) {
    csRaw.mitre_attack.forEach((m) => {
      const tid = normalizeTechniqueId(m?.technique_id);
      if (tid) techniques.add(tid);

      const tk = normalizeTacticKey(m?.tactic);
      if (tk) tactics.add(tk);
    });
  }

  // Secondary: backend-extracted technique ids
  if (Array.isArray(detection?.technique_ids)) {
    detection.technique_ids.forEach((id) => {
      const tid = normalizeTechniqueId(id);
      if (tid) techniques.add(tid);
    });
  }

  if (typeof detection?.technique_id === 'string') {
    const tid = normalizeTechniqueId(detection.technique_id);
    if (tid) techniques.add(tid);
  }

  // If we know the technique locally, attach its tactic
  techniques.forEach((tid) => {
    const tk = MITRE_TECHNIQUES[tid]?.tactic;
    if (tk) tactics.add(tk);
  });

  // Last-resort: if csRaw has tactic name fields
  const rawTk = normalizeTacticKey(csRaw?.tactic || detection?.tactic);
  if (rawTk) tactics.add(rawTk);

  return { tactics: [...tactics], techniques: [...techniques] };
};

/* ============================================================
   BADGES (exported) - FIXES YOUR BUILD ERROR
============================================================ */
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
      style={{ backgroundColor: tactic.color, color: tactic.textColor || '#ffffff' }}
      title={`MITRE ATT&CK Tactic: ${tactic.name}`}
    >
      {tactic.name}
      <ExternalLink className="w-3 h-3 ml-1" />
    </a>
  );
};

export const MitreTechniqueBadge = ({ techniqueId, size = 'md', techniqueNameOverride }) => {
  const local = MITRE_TECHNIQUES[techniqueId];
  const tacticKey = local?.tactic;
  const tactic = tacticKey ? MITRE_ATTACK_TACTICS[tacticKey] : null;

  const sizeClasses = {
    sm: 'text-xs px-2 py-0.5',
    md: 'text-sm px-3 py-1',
    lg: 'text-base px-4 py-2'
  };

  const name = techniqueNameOverride || local?.name || 'Unknown Technique';

  return (
    <a
      href={getMitreTechniqueUrl(techniqueId)}
      target="_blank"
      rel="noopener noreferrer"
      className={`inline-flex items-center ${sizeClasses[size]} rounded font-medium hover:opacity-80 transition-opacity`}
      style={{
        backgroundColor: (tactic?.color || '#6b7280') + '22',
        color: '#ffffff'
      }}
      title={name}
    >
      <Shield className="w-3 h-3 mr-1" />
      {techniqueId}: {name}
      <ExternalLink className="w-3 h-3 ml-1" />
    </a>
  );
};

/* ============================================================
   MATRIX COMPONENT
============================================================ */
export const MitreAttackMatrix = ({ detections }) => {
  const coverageStats = {};
  const techniqueFrequency = {};
  const techniqueNames = {}; // friendly names from CS when available

  (detections || []).forEach((det) => {
    const { tactics, techniques } = mapToMitreAttack(det);

    tactics.forEach((t) => {
      coverageStats[t] = (coverageStats[t] || 0) + 1;
    });

    techniques.forEach((tid) => {
      techniqueFrequency[tid] = (techniqueFrequency[tid] || 0) + 1;
    });

    // capture technique display names from CS
    det?.raw_data?.cs_raw?.mitre_attack?.forEach((m) => {
      const tid = normalizeTechniqueId(m?.technique_id);
      if (tid && m?.technique && !techniqueNames[tid]) {
        techniqueNames[tid] = m.technique;
      }
    });
  });

  const maxFrequency = Math.max(...Object.values(techniqueFrequency), 1);

  return (
    <div className="bg-white dark:bg-gray-800 rounded-lg shadow-lg p-6">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-xl font-bold text-gray-900 dark:text-white">MITRE ATT&CK Coverage</h3>
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

      {/* TACTICS */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3 mb-6">
        {Object.entries(MITRE_ATTACK_TACTICS).map(([key, tactic]) => {
          const count = coverageStats[key] || 0;
          const opacity = count > 0 ? Math.min(0.35 + (count / Math.max(detections?.length || 1, 1)) * 0.65, 1) : 0;

          return (
            <div
              key={key}
              className="rounded-lg p-3 text-center border-2 transition-all hover:scale-105"
              style={{
                backgroundColor: count > 0 ? tactic.color + Math.floor(opacity * 255).toString(16).padStart(2, '0') : 'transparent',
                borderColor: count > 0 ? tactic.color : '#374151'
              }}
              title={tactic.id}
            >
              <div className="text-xs font-semibold mb-1" style={{ color: count > 0 ? '#ffffff' : tactic.color }}>
                {tactic.name}
              </div>
              <div className="text-2xl font-bold" style={{ color: count > 0 ? '#ffffff' : '#9ca3af' }}>
                {count}
              </div>
            </div>
          );
        })}
      </div>

      {/* TECHNIQUES */}
      <h4 className="font-semibold mb-2 text-gray-900 dark:text-white">Most Frequent Techniques</h4>

      {Object.entries(techniqueFrequency).length > 0 ? (
        Object.entries(techniqueFrequency)
          .sort((a, b) => b[1] - a[1])
          .slice(0, 10)
          .map(([tid, count]) => {
            const name = MITRE_TECHNIQUES[tid]?.name || techniqueNames[tid] || 'Unknown Technique';
            const tacticKey = MITRE_TECHNIQUES[tid]?.tactic;
            const color = MITRE_ATTACK_TACTICS[tacticKey]?.color || '#6b7280';

            return (
              <div key={tid} className="mb-2">
                <div className="flex justify-between text-sm text-gray-800 dark:text-gray-200">
                  <a
                    href={getMitreTechniqueUrl(tid)}
                    target="_blank"
                    rel="noopener noreferrer"
                    className="hover:underline"
                  >
                    {tid}: {name}
                    <ExternalLink className="inline w-3 h-3 ml-1" />
                  </a>
                  <span className="font-semibold">{count}</span>
                </div>
                <div className="h-2 bg-gray-200 dark:bg-gray-700 rounded">
                  <div
                    className="h-2 rounded"
                    style={{
                      width: `${(count / maxFrequency) * 100}%`,
                      backgroundColor: color
                    }}
                  />
                </div>
              </div>
            );
          })
      ) : (
        <div className="text-center py-8 text-gray-500 dark:text-gray-400">
          <AlertTriangle className="w-10 h-10 mx-auto mb-2 opacity-50" />
          <p>No MITRE ATT&CK techniques mapped yet</p>
        </div>
      )}
    </div>
  );
};
