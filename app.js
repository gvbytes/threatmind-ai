const state = {
  projectName: '',
  projectDescription: '',
  projectIdea: '',
  components: [],
  diagramBase64: null,
  
  threats: [],
  attackTree: '',
  abuseCases: [],
  controls: [],
  
  apiProvider: 'Not available yet',
  apiModel: 'Still the API mechanism is in Development',
  apiKey: '',
  
  activeTab: 'stride'
};

const HEURISTICS = {
  frontend: {
    name: 'Web Frontend / Mobile Client',
    threats: [
      {
        id: 'T-FE-1', stride: 'S',
        title: 'Session Hijacking via Cookie Spoofing',
        description: 'Attackers capture or guess session cookies to impersonate authentic users.',
        likelihood: 2, impact: 3,
        mitigation: 'Implement secure, httpOnly, and SameSite flags for all session cookies.'
      },
      {
        id: 'T-FE-2', stride: 'T',
        title: 'Cross-Site Scripting (XSS) on Input Fields',
        description: 'Malicious scripts are injected into inputs and run in other users\' browsers.',
        likelihood: 3, impact: 2,
        mitigation: 'Implement strict output encoding and configure a Content Security Policy (CSP).'
      }
    ],
    abuseCases: [
      {
        title: 'Malicious Script Execution',
        actor: 'External Attacker',
        scenario: 'Attacker injects a script tag in a post. When users view it, the script steals cookies.'
      }
    ]
  },
  api: {
    name: 'API Gateway / Backend Server',
    threats: [
      {
        id: 'T-API-1', stride: 'S',
        title: 'API Client Impersonation',
        description: 'Attackers craft requests pretending to be trusted services due to weak auth.',
        likelihood: 2, impact: 3,
        mitigation: 'Implement Mutual TLS (mTLS) or secure JWT signature validation at the gateway.'
      },
      {
        id: 'T-API-2', stride: 'D',
        title: 'API Rate Limiting Exhaustion',
        description: 'Resource exhaustion via request flooding takes down backend instances.',
        likelihood: 3, impact: 2,
        mitigation: 'Configure rate limiting rules (token bucket) at the API Gateway level.'
      },
      {
        id: 'T-API-3', stride: 'E',
        title: 'Broken Object Level Authorization (IDOR)',
        description: 'Users alter ID parameters in requests to access other users\' records.',
        likelihood: 3, impact: 3,
        mitigation: 'Verify user ownership rights on every target object query.'
      }
    ],
    abuseCases: [
      {
        title: 'Resource Scraping via API',
        actor: 'Malicious User',
        scenario: 'A user runs a script to scrape user profiles by incrementing request ID integers.'
      }
    ]
  },
  database: {
    name: 'Database (SQL/NoSQL)',
    threats: [
      {
        id: 'T-DB-1', stride: 'T',
        title: 'SQL / NoSQL Query Injection',
        description: 'Attackers manipulate query inputs to run arbitrary SQL statements.',
        likelihood: 2, impact: 3,
        mitigation: 'Use parameterized queries, prepared statements, or ORMs.'
      },
      {
        id: 'T-DB-2', stride: 'I',
        title: 'Direct Database Exposure & Leakage',
        description: 'Unencrypted backups or open ports expose raw data directly.',
        likelihood: 2, impact: 3,
        mitigation: 'Enable at-rest encryption and disable database public network access.'
      }
    ],
    abuseCases: [
      {
        title: 'Database Schema Extraction',
        actor: 'SQLi Attacker',
        scenario: 'Attacker injects SQL union parameters to dump the system database schema.'
      }
    ]
  }
};

document.addEventListener('DOMContentLoaded', () => {
  initEventListeners();
  loadApiConfig();
  renderComponentTags();
  updateSessionsDropdown();
  logMessage("ThreatMind Workspace ready.", "success");
});

function logMessage(text, type = 'info') {
  const container = document.getElementById('consoleLogs');
  if (!container) return;
  const timestamp = new Date().toLocaleTimeString();
  const line = document.createElement('div');
  line.className = `log-line log-${type}`;
  line.innerText = `[${timestamp}] [${type.toUpperCase()}] ${text}`;
  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

function initEventListeners() {
  const uploadZone = document.getElementById('uploadZone');
  const fileInput = document.getElementById('architectureFile');
  
  uploadZone.addEventListener('click', () => fileInput.click());
  uploadZone.addEventListener('dragover', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--color-primary)';
  });
  uploadZone.addEventListener('dragleave', () => {
    uploadZone.style.borderColor = 'var(--border-color)';
  });
  uploadZone.addEventListener('drop', (e) => {
    e.preventDefault();
    uploadZone.style.borderColor = 'var(--border-color)';
    if (e.dataTransfer.files.length > 0) {
      handleFile(e.dataTransfer.files[0]);
    }
  });
  
  fileInput.addEventListener('change', (e) => {
    if (e.target.files.length > 0) {
      handleFile(e.target.files[0]);
    }
  });

  document.getElementById('btnRemovePreview').addEventListener('click', (e) => {
    e.stopPropagation();
    state.diagramBase64 = null;
    document.getElementById('previewContainer').style.display = 'none';
    document.getElementById('uploadText').style.display = 'block';
    fileInput.value = '';
    logMessage("Architecture diagram removed.", "info");
  });

  document.getElementById('btnAddComp').addEventListener('click', () => {
    const selector = document.getElementById('compSelector');
    const compType = selector.value;
    let mappedType = compType;
    if (compType === 'auth' || compType === 'storage') mappedType = 'api';
    
    if (mappedType && !state.components.includes(mappedType)) {
      state.components.push(mappedType);
      renderComponentTags();
      logMessage(`Added node: ${HEURISTICS[mappedType]?.name || mappedType}`, "info");
    }
  });

  const settingsBtn = document.getElementById('btnSettings');
  const settingsModal = document.getElementById('settingsModal');
  const modalClose = document.getElementById('modalClose');
  const settingsForm = document.getElementById('settingsForm');

  settingsBtn.addEventListener('click', () => {
    document.getElementById('apiProvider').value = state.apiProvider;
    document.getElementById('apiModel').value = state.apiModel;
    document.getElementById('apiKey').value = state.apiKey;
    settingsModal.style.display = 'grid';
  });

  modalClose.addEventListener('click', () => {
    settingsModal.style.display = 'none';
  });

  window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
      settingsModal.style.display = 'none';
    }
  });

  settingsForm.addEventListener('submit', (e) => {
    e.preventDefault();
    state.apiProvider = document.getElementById('apiProvider').value;
    state.apiModel = document.getElementById('apiModel').value.trim() || (state.apiProvider === 'gemini' ? 'gemini-1.5-flash' : 'gpt-4o-mini');
    state.apiKey = document.getElementById('apiKey').value.trim();
    saveApiConfig();
    settingsModal.style.display = 'none';
    logMessage(`Configured API: ${state.apiProvider.toUpperCase()} (${state.apiModel})`, "success");
  });

  document.getElementById('btnShowAddThreatModal').addEventListener('click', () => {
    document.getElementById('addThreatModal').style.display = 'grid';
  });

  document.getElementById('addThreatModalClose').addEventListener('click', () => {
    document.getElementById('addThreatModal').style.display = 'none';
  });

  document.getElementById('addThreatForm').addEventListener('submit', (e) => {
    e.preventDefault();
    const stride = document.getElementById('customStride').value;
    const title = document.getElementById('customTitle').value.trim();
    const component = document.getElementById('customComponent').value.trim();
    const likelihood = parseInt(document.getElementById('customLikelihood').value);
    const impact = parseInt(document.getElementById('customImpact').value);
    const description = document.getElementById('customDescription').value.trim();
    const mitigation = document.getElementById('customMitigation').value.trim();

    const uniqueId = `T-CUST-${Math.floor(Math.random() * 10000)}`;
    state.threats.push({
      id: uniqueId, stride, title, description, component, likelihood, impact,
      riskScore: likelihood * impact, mitigation
    });

    state.controls.push({
      title: `Mitigate ${title}`,
      description: mitigation,
      checked: false,
      threatMap: uniqueId
    });

    logMessage(`Added custom threat: "${title}"`, "success");
    document.getElementById('addThreatModal').style.display = 'none';
    document.getElementById('addThreatForm').reset();
    renderTabContent();
    saveCurrentSessionState();
  });

  document.getElementById('btnGenerate').addEventListener('click', () => {
    state.projectName = document.getElementById('projectName').value.trim();
    state.projectDescription = document.getElementById('projectDesc').value.trim();
    state.projectIdea = document.getElementById('projectIdea').value.trim();

    if (!state.projectName) {
      alert('Please enter a Project Name.');
      return;
    }
    generateThreatModel();
  });

  document.getElementById('savedSessions').addEventListener('change', (e) => {
    if (e.target.value) {
      loadSessionState(e.target.value);
    }
  });

  document.querySelectorAll('.tab').forEach(tab => {
    tab.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tab.classList.add('active');
      state.activeTab = tab.dataset.tab;
      renderTabContent();
    });
  });

  document.getElementById('btnExport').addEventListener('click', () => {
    exportToMarkdown();
  });
}

function handleFile(file) {
  if (!file.type.startsWith('image/')) return;
  const reader = new FileReader();
  reader.onload = (e) => {
    state.diagramBase64 = e.target.result;
    document.getElementById('previewImg').src = state.diagramBase64;
    document.getElementById('previewContainer').style.display = 'block';
    document.getElementById('uploadText').style.display = 'none';
    logMessage("Uploaded architecture diagram.", "success");
  };
  reader.readAsDataURL(file);
}

function renderComponentTags() {
  const container = document.getElementById('componentTags');
  container.innerHTML = '';
  state.components.forEach(comp => {
    const tag = document.createElement('div');
    tag.className = 'component-tag';
    tag.innerHTML = `
      <span>${HEURISTICS[comp]?.name || comp}</span>
      <button onclick="removeComponent('${comp}')">&times;</button>
    `;
    container.appendChild(tag);
  });
}

window.removeComponent = function(comp) {
  state.components = state.components.filter(c => c !== comp);
  renderComponentTags();
  logMessage(`Removed component: ${HEURISTICS[comp]?.name || comp}`, "info");
};

function saveApiConfig() {
  localStorage.setItem('threatmind_provider', state.apiProvider);
  localStorage.setItem('threatmind_model', state.apiModel);
  localStorage.setItem('threatmind_key', state.apiKey);
}

function loadApiConfig() {
  const provider = localStorage.getItem('threatmind_provider');
  const model = localStorage.getItem('threatmind_model');
  const key = localStorage.getItem('threatmind_key');
  if (provider) state.apiProvider = provider;
  if (model) state.apiModel = model;
  if (key) state.apiKey = key;
}

async function generateThreatModel() {
  document.getElementById('loadingOverlay').style.display = 'flex';
  logMessage(`Analyzing security parameters for: ${state.projectName}`, "info");
  
  try {
    if (state.apiKey) {
      logMessage("Contacting external LLM Service...", "info");
      await generateThreatModelWithAI();
    } else {
      logMessage("Using offline rule matcher...", "info");
      await new Promise(resolve => setTimeout(resolve, 800));
      generateThreatModelWithHeuristics();
    }
    
    logMessage(`Found ${state.threats.length} threats.`, "warning");
    
    document.getElementById('welcomeScreen').style.display = 'none';
    document.getElementById('dashboardOutput').style.display = 'block';
    document.getElementById('btnExport').style.display = 'inline-flex';
    document.getElementById('btnShowAddThreatModal').style.display = 'inline-flex';
    
    renderTabContent();
    saveCurrentSessionState();
  } catch (error) {
    logMessage(`Analysis error: ${error.message}`, "error");
    alert('Error generating model: ' + error.message);
  } finally {
    document.getElementById('loadingOverlay').style.display = 'none';
  }
}

function generateThreatModelWithHeuristics() {
  const selectedComps = state.components.length > 0 ? state.components : ['frontend', 'api', 'database'];
  state.threats = [];
  state.abuseCases = [];
  state.controls = [];

  selectedComps.forEach(compKey => {
    const compData = HEURISTICS[compKey];
    if (!compData) return;

    compData.threats.forEach(t => {
      const uniqueId = `T-${compKey.toUpperCase()}-${Math.floor(Math.random() * 1000)}`;
      state.threats.push({
        id: uniqueId, stride: t.stride, title: t.title, description: t.description,
        component: compData.name, likelihood: t.likelihood, impact: t.impact,
        riskScore: t.likelihood * t.impact, mitigation: t.mitigation
      });

      state.controls.push({
        title: `Mitigate ${t.title}`, description: t.mitigation,
        checked: false, threatMap: uniqueId
      });
    });

    compData.abuseCases.forEach(ac => {
      state.abuseCases.push({
        title: ac.title, actor: ac.actor, scenario: ac.scenario
      });
    });
  });

  state.attackTree = generateMermaidTree(selectedComps);
}

function generateMermaidTree(selectedComps) {
  let tree = 'graph TD\n';
  tree += `  Root["Compromise ${state.projectName}"] --> FE["Web Frontend"]\n`;
  if (selectedComps.includes('api')) {
    tree += `  Root --> API["Backend API Service"]\n`;
    tree += `  FE --> API\n`;
  }
  if (selectedComps.includes('database')) {
    tree += `  Root --> DB[("Database Server")]\n`;
    if (selectedComps.includes('api')) tree += `  API --> DB\n`;
    else tree += `  FE --> DB\n`;
  }
  return tree;
}

async function generateThreatModelWithAI() {
  const componentNames = state.components.map(c => HEURISTICS[c]?.name || c).join(', ');
  
  const systemPrompt = `You are ThreatMind AI. Generate a security threat model in JSON format.
  Input details:
  Project: ${state.projectName}
  Description: ${state.projectDescription}
  Components: ${componentNames}
  Parameters: ${state.projectIdea}

  Response must be strict JSON output without markdown blocks. Schema:
  {
    "threats": [{"id": "unique-id", "stride": "S"|"T"|"R"|"I"|"D"|"E", "title": "...", "description": "...", "component": "...", "likelihood": 1-3, "impact": 1-3, "riskScore": 1-9, "mitigation": "..."}],
    "attackTree": "Valid Mermaid.js graph code",
    "abuseCases": [{"title": "...", "actor": "...", "scenario": "..."}],
    "controls": [{"title": "Mitigation Title", "description": "...", "threatMap": "associated threat id"}]
  }`;

  let responseText = '';
  
  if (state.apiProvider === 'gemini') {
    const url = `https://generativelanguage.googleapis.com/v1/models/${state.apiModel}:generateContent?key=${state.apiKey}`;
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts: [{ text: systemPrompt }] }] })
    });
    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      throw new Error(errorJson?.error?.message || `HTTP ${response.status}`);
    }
    const data = await response.json();
    responseText = data.candidates[0].content.parts[0].text;
  } else {
    const url = 'https://api.openai.com/v1/chat/completions';
    const response = await fetch(url, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': `Bearer ${state.apiKey}`
      },
      body: JSON.stringify({
        model: state.apiModel,
        messages: [{ role: 'user', content: systemPrompt }]
      })
    });
    if (!response.ok) {
      const errorJson = await response.json().catch(() => ({}));
      throw new Error(errorJson?.error?.message || `HTTP ${response.status}`);
    }
    const data = await response.json();
    responseText = data.choices[0].message.content;
  }

  const jsonMatch = responseText.match(/\{[\s\S]*\}/);
  let cleanText = jsonMatch ? jsonMatch[0] : responseText;
  cleanText = cleanText.trim();
  if (cleanText.startsWith('```')) {
    cleanText = cleanText.replace(/^```[a-zA-Z]*\n?/, '').replace(/```$/, '').trim();
  }

  const parsed = JSON.parse(cleanText);
  state.threats = parsed.threats || parsed.threat_model || [];
  state.attackTree = parsed.attackTree || parsed.attack_tree || '';
  state.abuseCases = parsed.abuseCases || parsed.abuse_cases || [];
  
  const rawControls = parsed.controls || parsed.security_controls || [];
  state.controls = rawControls.map(c => ({ ...c, checked: false }));
}

function renderTabContent() {
  const container = document.getElementById('tabContent');
  container.innerHTML = '';
  
  if (state.activeTab === 'stride') {
    renderStrideTab(container);
  } else if (state.activeTab === 'tree') {
    renderTreeTab(container);
  } else if (state.activeTab === 'abuse') {
    renderAbuseTab(container);
  } else if (state.activeTab === 'risk') {
    renderRiskTab(container);
  } else if (state.activeTab === 'controls') {
    renderControlsTab(container);
  }
}

function renderStrideTab(container) {
  container.innerHTML = `
    <div class="card full-width">
      <div class="card-title">
        <div class="card-title-left">
          <svg width="18" height="18" fill="none" stroke="currentColor" stroke-width="2" viewBox="0 0 24 24"><path d="M12 15v2m-6 4h12a2 2 0 002-2v-6a2 2 0 00-2-2H6a2 2 0 00-2 2v6a2 2 0 002 2zm10-10V7a4 4 0 00-8 0v4h8z"></path></svg>
          STRIDE Model (Click text inline to edit)
        </div>
      </div>
      <div class="threats-list" id="threatsList"></div>
    </div>
  `;
  
  const list = document.getElementById('threatsList');
  if (state.threats.length === 0) {
    list.innerHTML = '<p style="color: var(--text-muted);">No threats generated.</p>';
    return;
  }

  state.threats.forEach((t, idx) => {
    const item = document.createElement('div');
    item.className = 'threat-item';
    
    const riskScoreVal = t.riskScore || (t.likelihood * t.impact);
    let rClass = riskScoreVal >= 6 ? 'risk-high' : (riskScoreVal >= 4 ? 'risk-medium' : 'risk-low');
    let rLabel = riskScoreVal >= 6 ? 'High' : (riskScoreVal >= 4 ? 'Medium' : 'Low');

    item.innerHTML = `
      <div class="threat-header" onclick="toggleThreatBody(this)">
        <div class="threat-title-group">
          <span class="stride-badge stride-${t.stride.toLowerCase()}">${t.stride}</span>
          <span class="threat-title" contenteditable="true" onclick="event.stopPropagation()" onblur="saveInlineEdit(this, 'title', ${idx})">${t.title}</span>
        </div>
        <div class="threat-header-actions" onclick="event.stopPropagation()">
          <span class="risk-pill ${rClass}">${rLabel}</span>
          <button class="btn-small btn-small-danger" onclick="deleteThreat(${idx})">&times;</button>
        </div>
      </div>
      <div class="threat-body">
        <p contenteditable="true" onblur="saveInlineEdit(this, 'description', ${idx})" style="margin-bottom: 1rem; padding:0.25rem; border-radius:4px;">${t.description}</p>
        <div class="threat-meta-grid">
          <div class="meta-item">
            <h5>Target Component</h5>
            <p contenteditable="true" onblur="saveInlineEdit(this, 'component', ${idx})">${t.component}</p>
          </div>
          <div class="meta-item">
            <h5>Risk Level</h5>
            <p>Likelihood (${t.likelihood}) x Impact (${t.impact}) = Score: ${riskScoreVal}</p>
          </div>
          <div class="meta-item" style="grid-column: span 2;">
            <h5>Mitigation Control</h5>
            <p contenteditable="true" onblur="saveInlineEdit(this, 'mitigation', ${idx})" style="color: var(--color-primary); padding:0.25rem; border-radius:4px;">${t.mitigation}</p>
          </div>
        </div>
      </div>
    `;
    list.appendChild(item);
  });
}

window.toggleThreatBody = function(hdr) {
  const body = hdr.nextElementSibling;
  body.style.display = body.style.display === 'block' ? 'none' : 'block';
};

window.saveInlineEdit = function(element, fieldKey, idx) {
  const value = element.innerText.trim();
  if (value) {
    state.threats[idx][fieldKey] = value;
    
    if (fieldKey === 'mitigation') {
      const ctrl = state.controls.find(c => c.threatMap === state.threats[idx].id);
      if (ctrl) ctrl.description = value;
    } else if (fieldKey === 'title') {
      const ctrl = state.controls.find(c => c.threatMap === state.threats[idx].id);
      if (ctrl) ctrl.title = `Mitigate ${value}`;
    }
    
    logMessage(`Saved edit on threat field: "${fieldKey}"`, "info");
    saveCurrentSessionState();
  }
};

window.deleteThreat = function(idx) {
  const t = state.threats[idx];
  logMessage(`Removed threat vector: "${t.title}"`, "info");
  state.controls = state.controls.filter(c => c.threatMap !== t.id);
  state.threats.splice(idx, 1);
  saveCurrentSessionState();
  renderTabContent();
};

function renderTreeTab(container) {
  container.innerHTML = `
    <div class="card full-width">
      <div class="card-title">Attack Tree Visualizer</div>
      <div class="attack-tree-container">
        <div class="mermaid" id="attackTreeMermaid">${state.attackTree}</div>
      </div>
    </div>
  `;
  if (window.mermaid) {
    try { window.mermaid.init(undefined, document.getElementById('attackTreeMermaid')); } 
    catch (e) { console.error('Mermaid render error', e); }
  }
}

function renderAbuseTab(container) {
  container.innerHTML = `
    <div class="card full-width">
      <div class="card-title">Abuse Case Scenarios</div>
      <div class="abuse-cases-grid" id="abuseCasesList"></div>
    </div>
  `;
  const list = document.getElementById('abuseCasesList');
  if (state.abuseCases.length === 0) {
    list.innerHTML = '<p style="color: var(--text-muted);">No abuse cases generated.</p>';
    return;
  }
  state.abuseCases.forEach(ac => {
    const card = document.createElement('div');
    card.className = 'abuse-card';
    card.innerHTML = `
      <div class="abuse-header">
        <span class="abuse-title">${ac.title}</span>
        <span class="abuse-actor">${ac.actor}</span>
      </div>
      <p class="abuse-desc">${ac.scenario}</p>
    `;
    list.appendChild(card);
  });
}

function renderRiskTab(container) {
  let high = 0, med = 0, low = 0;
  state.threats.forEach(t => {
    const score = t.riskScore || (t.likelihood * t.impact);
    if (score >= 6) high++;
    else if (score >= 4) med++;
    else low++;
  });

  container.innerHTML = `
    <div class="card risk-matrix-card">
      <div class="card-title">Risk Scoring Grid</div>
      <div class="risk-matrix">
        <div class="matrix-label">Impact</div>
        <div class="matrix-label">Low</div><div class="matrix-label">Medium</div><div class="matrix-label">High</div>
        <div class="matrix-label">High (3)</div><div class="matrix-cell cell-med">3</div><div class="matrix-cell cell-high">6</div><div class="matrix-cell cell-high">9</div>
        <div class="matrix-label">Med (2)</div><div class="matrix-cell cell-low">2</div><div class="matrix-cell cell-med">4</div><div class="matrix-cell cell-high">6</div>
        <div class="matrix-label">Low (1)</div><div class="matrix-cell cell-low">1</div><div class="matrix-cell cell-low">2</div><div class="matrix-cell cell-med">3</div>
      </div>
    </div>
    <div class="card">
      <div class="card-title">Summary Metrics</div>
      <div class="matrix-stat">
        <div class="stat-item"><div class="stat-val color-h">${high}</div><div class="stat-lbl">High Risk</div></div>
        <div class="stat-item"><div class="stat-val color-m">${med}</div><div class="stat-lbl">Medium Risk</div></div>
        <div class="stat-item"><div class="stat-val color-l">${low}</div><div class="stat-lbl">Low Risk</div></div>
      </div>
    </div>
  `;
}

function renderControlsTab(container) {
  container.innerHTML = `
    <div class="card full-width">
      <div class="card-title">Mitigations Checklist</div>
      <div class="controls-list" id="controlsList"></div>
    </div>
  `;
  const list = document.getElementById('controlsList');
  state.controls.forEach((c, idx) => {
    const item = document.createElement('div');
    item.className = 'control-item';
    item.innerHTML = `
      <input type="checkbox" class="control-checkbox" ${c.checked ? 'checked' : ''} onchange="toggleControl(${idx})">
      <div class="control-info">
        <div class="control-label"><span>${c.title}</span><span class="control-map">${c.threatMap}</span></div>
        <p class="control-desc">${c.description}</p>
      </div>
    `;
    list.appendChild(item);
  });
}

window.toggleControl = function(idx) {
  state.controls[idx].checked = !state.controls[idx].checked;
  saveCurrentSessionState();
};

function saveCurrentSessionState() {
  if (!state.projectName) return;
  const saved = JSON.parse(localStorage.getItem('threatmind_sessions') || '{}');
  saved[state.projectName] = {
    projectName: state.projectName,
    projectDescription: state.projectDescription,
    projectIdea: state.projectIdea,
    components: state.components,
    diagramBase64: state.diagramBase64,
    threats: state.threats,
    attackTree: state.attackTree,
    abuseCases: state.abuseCases,
    controls: state.controls
  };
  localStorage.setItem('threatmind_sessions', JSON.stringify(saved));
  updateSessionsDropdown();
}

function loadSessionState(name) {
  const saved = JSON.parse(localStorage.getItem('threatmind_sessions') || '{}');
  const d = saved[name];
  if (!d) return;

  state.projectName = d.projectName;
  state.projectDescription = d.projectDescription;
  state.projectIdea = d.projectIdea;
  state.components = d.components || [];
  state.diagramBase64 = d.diagramBase64;
  state.threats = d.threats || [];
  state.attackTree = d.attackTree || '';
  state.abuseCases = d.abuseCases || [];
  state.controls = d.controls || [];

  document.getElementById('projectName').value = state.projectName;
  document.getElementById('projectDesc').value = state.projectDescription;
  document.getElementById('projectIdea').value = state.projectIdea;
  
  if (state.diagramBase64) {
    document.getElementById('previewImg').src = state.diagramBase64;
    document.getElementById('previewContainer').style.display = 'block';
    document.getElementById('uploadText').style.display = 'none';
  } else {
    document.getElementById('previewContainer').style.display = 'none';
    document.getElementById('uploadText').style.display = 'block';
  }
  renderComponentTags();

  document.getElementById('welcomeScreen').style.display = 'none';
  document.getElementById('dashboardOutput').style.display = 'block';
  document.getElementById('btnExport').style.display = 'inline-flex';
  document.getElementById('btnShowAddThreatModal').style.display = 'inline-flex';
  
  renderTabContent();
  logMessage(`Loaded session: "${name}"`, "success");
}

function updateSessionsDropdown() {
  const dd = document.getElementById('savedSessions');
  if (!dd) return;
  dd.innerHTML = '<option value="">-- Load Saved Session --</option>';
  const saved = JSON.parse(localStorage.getItem('threatmind_sessions') || '{}');
  Object.keys(saved).forEach(name => {
    const opt = document.createElement('option');
    opt.value = name; opt.innerText = name;
    dd.appendChild(opt);
  });
}

function exportToMarkdown() {
  let md = `# Threat Modeling Report - ${state.projectName}\n\n`;
  md += `**Date:** ${new Date().toLocaleDateString()}\n`;
  md += `**Description:** ${state.projectDescription}\n`;
  md += `**Components:** ${state.components.join(', ')}\n\n`;
  md += `## 1. STRIDE Threats\n\n`;
  md += `| ID | Category | Title | Component | Risk | Mitigation |\n|---|---|---|---|---|---|\n`;
  state.threats.forEach(t => {
    md += `| ${t.id} | ${t.stride} | ${t.title} | ${t.component} | ${t.riskScore} | ${t.mitigation} |\n`;
  });
  
  md += `\n## 2. Attack Tree (Mermaid.js)\n\n\`\`\`mermaid\n${state.attackTree}\n\`\`\`\n`;
  
  const blob = new Blob([md], { type: 'text/markdown;charset=utf-8;' });
  const url = URL.createObjectURL(blob);
  const link = document.createElement('a');
  link.setAttribute('href', url);
  link.setAttribute('download', `${state.projectName.toLowerCase().replace(/\s+/g, '_')}_threat_model.md`);
  document.body.appendChild(link);
  link.click();
  document.body.removeChild(link);
}
//Still developement is going on, and I can't gurantee how much time it will take for the full production level development. Still learning and developing this shitt.