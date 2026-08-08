/**
 * ThreatMind AI - Threat Modeling & STRIDE Security Workbench
 * Modern Monochrome Engine & Multi-Provider Architecture
 */

// Preset architecture templates
const ARCHITECTURE_PRESETS = {
  fintech: {
    name: 'Payments Gateway & Settlement',
    desc: 'Multi-tenant payments processing service handling credit card transactions and merchant settlement via external banking APIs.',
    constraints: 'Must meet PCI-DSS Level 1 requirements. Mutual TLS between internal microservices. Data encrypted at rest using KMS keys.',
    components: ['frontend', 'api', 'microservice', 'database', 'storage', 'auth']
  },
  genai: {
    name: 'Autonomous AI Agent & RAG Stack',
    desc: 'Multi-agent orchestration platform executing automated code synthesis, vector document retrieval, and external tool execution.',
    constraints: 'OWASP Top 10 for LLMs compliance. Strict execution sandboxing for generated code. Prompt injection boundaries on external retrieval.',
    components: ['frontend', 'api', 'llm', 'database', 'cache', 'storage', 'auth']
  },
  ecommerce: {
    name: 'E-Commerce Platform & Mobile Store',
    desc: 'High-traffic retail platform with mobile app storefront, shopping cart sessions, inventory catalog, and third-party payment checkout.',
    constraints: 'High-availability during flash sales. Distributed session caching. Strict customer PII protection (GDPR/CCPA).',
    components: ['frontend', 'mobile', 'api', 'cache', 'database', 'queue', 'storage']
  },
  cloud: {
    name: 'Cloud Microservices & Event Mesh',
    desc: 'Distributed microservices architecture communicating via asynchronous Kafka message brokers and centralized API Gateway.',
    constraints: 'Zero-trust network architecture. Asynchronous event decoupling with dead-letter queue recovery.',
    components: ['api', 'microservice', 'queue', 'database', 'nosql', 'cache', 'auth']
  }
};

// Provider configurations
const PROVIDER_CONFIGS = {
  nvidia: {
    name: 'NVIDIA NIM',
    baseUrl: 'https://integrate.api.nvidia.com/v1',
    defaultModel: 'meta/llama-3.3-70b-instruct',
    helpText: 'Free credits available at build.nvidia.com. High performance on Llama-3.3-70B and DeepSeek-R1.',
    isOpenAICompatible: true
  },
  groq: {
    name: 'Groq Cloud',
    baseUrl: 'https://api.groq.com/openai/v1',
    defaultModel: 'llama-3.3-70b-versatile',
    helpText: 'Ultra-fast inference with a generous free tier.',
    isOpenAICompatible: true
  },
  openrouter: {
    name: 'OpenRouter',
    baseUrl: 'https://openrouter.ai/api/v1',
    defaultModel: 'meta-llama/llama-3.3-70b-instruct:free',
    helpText: 'Free model tier available (meta-llama/llama-3.3-70b-instruct:free).',
    isOpenAICompatible: true
  },
  gemini: {
    name: 'Google Gemini',
    baseUrl: 'https://generativelanguage.googleapis.com',
    defaultModel: 'gemini-1.5-flash',
    helpText: 'Google AI Studio API key. Native support for architecture image analysis.',
    isOpenAICompatible: false
  },
  openai: {
    name: 'OpenAI',
    baseUrl: 'https://api.openai.com/v1',
    defaultModel: 'gpt-4o-mini',
    helpText: 'Official OpenAI API key.',
    isOpenAICompatible: true
  },
  ollama: {
    name: 'Ollama (Local / Private)',
    baseUrl: 'http://localhost:11434/v1',
    defaultModel: 'llama3.3',
    helpText: '100% private, local threat modeling. Run "ollama run llama3.3" on your machine.',
    isOpenAICompatible: true
  },
  custom: {
    name: 'Custom OpenAI-Compatible',
    baseUrl: 'http://localhost:8000/v1',
    defaultModel: 'default-model',
    helpText: 'Any vLLM, LocalAI, or custom OpenAI-compatible endpoint.',
    isOpenAICompatible: true
  }
};

const STRIDE_NAMES = {
  S: 'Spoofing',
  T: 'Tampering',
  R: 'Repudiation',
  I: 'Information Disclosure',
  D: 'Denial of Service',
  E: 'Elevation of Privilege'
};

const HEURISTICS = {
  frontend: {
    name: 'Web Frontend (SPA / React)',
    threats: [
      {
        stride: 'S',
        title: 'Session Hijacking via Insecure Cookie Storage',
        description: 'Session tokens stored in localStorage or cookies without HttpOnly/SameSite flags are susceptible to theft by malicious scripts.',
        likelihood: 2, impact: 3,
        mitigation: 'Store authentication tokens in HttpOnly, Secure, SameSite=Strict cookies; implement token rotation.'
      },
      {
        stride: 'T',
        title: 'DOM-based Cross-Site Scripting (XSS)',
        description: 'Unsanitized user-controlled URL fragments or inputs rendered directly into the DOM execute arbitrary client scripts.',
        likelihood: 3, impact: 2,
        mitigation: 'Enforce strict output encoding, sanitize HTML with DOMPurify, and implement a rigid Content Security Policy (CSP).'
      },
      {
        stride: 'T',
        title: 'Subresource Integrity (SRI) Tampering',
        description: 'Compromised third-party CDN scripts execute malicious code in the context of the user application.',
        likelihood: 2, impact: 3,
        mitigation: 'Enforce Subresource Integrity (SRI) hashes on all external assets and restrict CDN domains via CSP.'
      }
    ],
    abuseCases: [
      {
        title: 'Stored XSS Token Exfiltration',
        actor: 'External Adversary',
        scenario: 'Attacker injects script payload into user profile. When an administrator inspects the profile, the script executes and exfiltrates the admin session.'
      }
    ]
  },
  mobile: {
    name: 'Mobile Client (iOS / Android)',
    threats: [
      {
        stride: 'I',
        title: 'Insecure Local Data Storage',
        description: 'Sensitive credentials, refresh tokens, or PII stored in unencrypted SharedPreferences / NSUserDefaults.',
        likelihood: 2, impact: 3,
        mitigation: 'Use platform keychains (Android EncryptedSharedPreferences / iOS Keychain Services) with biometric gates.'
      },
      {
        stride: 'T',
        title: 'Missing SSL / TLS Certificate Pinning',
        description: 'Adversary installs a custom CA certificate on the mobile device to intercept and manipulate TLS traffic.',
        likelihood: 2, impact: 3,
        mitigation: 'Implement dynamic SSL Pinning for all API endpoints using Network Security Config or pinning libraries.'
      }
    ],
    abuseCases: [
      {
        title: 'Man-In-The-Middle API Tampering',
        actor: 'Local Network Attacker',
        scenario: 'Attacker proxies mobile traffic through Burp Suite on a rooted device to alter transactional parameters before they hit the server.'
      }
    ]
  },
  api: {
    name: 'API Gateway & Reverse Proxy',
    threats: [
      {
        stride: 'S',
        title: 'JWT Algorithm Confusion & Spoofing',
        description: 'API Gateway fails to enforce strict asymmetric algorithms (RS256 vs HS256), allowing forged token validation.',
        likelihood: 2, impact: 3,
        mitigation: 'Explicitly restrict accepted JWT algorithms in validator config; reject tokens signed with "none" or symmetric keys.'
      },
      {
        stride: 'D',
        title: 'Distributed Rate-Limit Exhaustion',
        description: 'Absence of token-bucket rate limiting permits resource exhaustion through high-frequency distributed API bursts.',
        likelihood: 3, impact: 2,
        mitigation: 'Enforce IP-based and user-based token-bucket rate limits at the API Gateway level backed by Redis.'
      },
      {
        stride: 'E',
        title: 'Broken Object Level Authorization (BOLA / IDOR)',
        description: 'Endpoints expose sequential or predictable database keys without checking user ownership permissions.',
        likelihood: 3, impact: 3,
        mitigation: 'Enforce strict tenancy and object ownership authorization checks on every data query.'
      }
    ],
    abuseCases: [
      {
        title: 'Systematic Customer Record Scraping',
        actor: 'Authenticated Malicious User',
        scenario: 'User exploits BOLA by iterating over /api/v1/orders/{id} to harvest competitor transaction details.'
      }
    ]
  },
  microservice: {
    name: 'Core Backend Microservice',
    threats: [
      {
        stride: 'S',
        title: 'Unauthenticated East-West Service Communication',
        description: 'Internal microservice endpoints trust internal network packets without cryptographic verification.',
        likelihood: 2, impact: 3,
        mitigation: 'Enforce Mutual TLS (mTLS) with SPIFFE/SPIRE identities or signed internal service tokens.'
      },
      {
        stride: 'D',
        title: 'Cascading Dependency Failure',
        description: 'Unbounded synchronous HTTP calls to internal services exhaust connection thread pools when one node fails.',
        likelihood: 3, impact: 2,
        mitigation: 'Implement circuit breakers (e.g. Resilience4j / Envoy), strict timeouts, and asynchronous message decoupling.'
      }
    ],
    abuseCases: [
      {
        title: 'Lateral Movement Post-Pod Compromise',
        actor: 'Compromised Microservice',
        scenario: 'Attacker gains RCE on a public-facing service and uses the unsegmented internal network to query internal billing endpoints.'
      }
    ]
  },
  database: {
    name: 'Relational Database (SQL)',
    threats: [
      {
        stride: 'T',
        title: 'SQL Injection via Dynamic Concatenation',
        description: 'Raw SQL statements dynamically concatenate user inputs, allowing arbitrary query execution.',
        likelihood: 2, impact: 3,
        mitigation: 'Mandate parameterized queries, prepared statements, or strict typed ORMs across all queries.'
      },
      {
        stride: 'I',
        title: 'Unencrypted Database Backups & Storage Volumes',
        description: 'Database snapshot archives or disk volumes are stored without encryption at rest.',
        likelihood: 2, impact: 3,
        mitigation: 'Enable AES-256 transparent data encryption (TDE) for disks and encrypt backup dumps with KMS keys.'
      },
      {
        stride: 'R',
        title: 'Missing Immutable Audit Logging for Admin Queries',
        description: 'Database administrative modifications are not forwarded to a tamper-proof centralized SIEM.',
        likelihood: 2, impact: 2,
        mitigation: 'Stream query audit logs (e.g. pgAudit) to append-only cloud storage with retention lock.'
      }
    ],
    abuseCases: [
      {
        title: 'Blind SQL Injection Data Dump',
        actor: 'External Attacker',
        scenario: 'Attacker leverages time-based SQL injection on a search endpoint to reconstruct user credentials character by character.'
      }
    ]
  },
  nosql: {
    name: 'NoSQL Database (MongoDB / DynamoDB)',
    threats: [
      {
        stride: 'T',
        title: 'NoSQL Operator Injection',
        description: 'JSON request bodies pass operator keys ($gt, $ne, $where) directly into database query objects.',
        likelihood: 2, impact: 3,
        mitigation: 'Sanitize query inputs by casting all values to primitives and stripping MongoDB query operators.'
      },
      {
        stride: 'E',
        title: 'Schema-less Property Overwriting (Mass Assignment)',
        description: 'Client payloads include administrative attributes (isAdmin, role) that are persisted directly without schema filtering.',
        likelihood: 3, impact: 3,
        mitigation: 'Use explicit DTOs and schema validators (Zod/Pydantic) to strictly reject unexpected properties.'
      }
    ],
    abuseCases: [
      {
        title: 'Authentication Bypass via Operator Injection',
        actor: 'Adversary',
        scenario: 'Attacker submits {"username": "admin", "password": {"$ne": ""}} to bypass authentication logic.'
      }
    ]
  },
  cache: {
    name: 'In-Memory Cache (Redis)',
    threats: [
      {
        stride: 'T',
        title: 'Cache Poisoning & SSRF Injection',
        description: 'Unsanitized cache keys allow attackers to overwrite global shared state or inject malicious response bodies.',
        likelihood: 2, impact: 3,
        mitigation: 'Cryptographically hash or strictly sanitize cache key inputs; namespace all cache keys by tenant.'
      },
      {
        stride: 'I',
        title: 'Plaintext Cache Storage of Sensitive Records',
        description: 'PII, session secrets, or tokens stored in cleartext in Redis without encryption or network auth.',
        likelihood: 2, impact: 3,
        mitigation: 'Enforce Redis ACL authentication, TLS transport encryption, and client-side encryption for sensitive objects.'
      }
    ],
    abuseCases: [
      {
        title: 'Shared Cache De-synchronization',
        actor: 'Malicious Tenant',
        scenario: 'Attacker in a multi-tenant platform manipulates cache keys to poison the cached responses served to other tenants.'
      }
    ]
  },
  storage: {
    name: 'Cloud Object Storage (S3 / Blob)',
    threats: [
      {
        stride: 'I',
        title: 'Public Bucket ACL Misconfiguration',
        description: 'Object storage buckets configured with permissive read policies allow unauthenticated downloads of sensitive assets.',
        likelihood: 2, impact: 3,
        mitigation: 'Enable S3 Block Public Access globally, use pre-signed URLs with short lifespans (<=15 mins).'
      },
      {
        stride: 'T',
        title: 'Arbitrary File Overwrite & Path Traversal',
        description: 'File upload endpoints permit user-supplied filenames containing path traversal characters ("../../").',
        likelihood: 2, impact: 3,
        mitigation: 'Generate randomized UUID keys for uploaded files; validate MIME types and file signatures server-side.'
      }
    ],
    abuseCases: [
      {
        title: 'Unauthenticated PII Extraction via Open Bucket',
        actor: 'Security Researcher / Attacker',
        scenario: 'Attacker brute-forces company S3 bucket names using OSINT and dumps thousands of customer KYC document scans.'
      }
    ]
  },
  auth: {
    name: 'Identity Provider & Auth (OAuth2 / OIDC)',
    threats: [
      {
        stride: 'S',
        title: 'OAuth2 Authorization Code Redirection Tampering',
        description: 'Permissive redirect_uri validation allows attackers to steal authorization codes via open redirectors.',
        likelihood: 2, impact: 3,
        mitigation: 'Enforce exact string matching for redirect URIs and mandate PKCE (RFC 7636) for all clients.'
      },
      {
        stride: 'S',
        title: 'Credential Stuffing & Password Spraying',
        description: 'Absence of account lockout and CAPTCHA enables automated credential stuffing attacks.',
        likelihood: 3, impact: 3,
        mitigation: 'Implement progressive delays, WebAuthn MFA, and breached credential checks (HaveIBeenPwned API).'
      }
    ],
    abuseCases: [
      {
        title: 'Account Takeover via Weak Redirect URI',
        actor: 'Phishing Attacker',
        scenario: 'Attacker registers malicious URI subdomain, tricks user into OAuth flow, and captures authorization code to hijack account.'
      }
    ]
  },
  queue: {
    name: 'Message Broker (Kafka / RabbitMQ)',
    threats: [
      {
        stride: 'T',
        title: 'Message Tampering without Signature Verification',
        description: 'Consumers process asynchronous queue payloads without verifying message origin integrity.',
        likelihood: 2, impact: 3,
        mitigation: 'Sign message payloads using HMAC or asymmetric signatures; validate schema versions on consumption.'
      },
      {
        stride: 'D',
        title: 'Poison Pill Message Queue Hang',
        description: 'Malformed payloads trigger uncaught consumer exceptions, causing infinite redelivery loops and consumer crash.',
        likelihood: 3, impact: 2,
        mitigation: 'Implement Dead Letter Queues (DLQ) with max retry counts and strict JSON schema validation.'
      }
    ],
    abuseCases: [
      {
        title: 'Consumer Thread Starvation via Poison Messages',
        actor: 'Internal Attacker',
        scenario: 'Attacker pushes a payload that causes deserialization errors, blocking downstream queue partitions.'
      }
    ]
  },
  llm: {
    name: 'LLM & AI Agent Orchestrator',
    threats: [
      {
        stride: 'T',
        title: 'Indirect Prompt Injection via External Content',
        description: 'Untrusted user inputs, web search results, or retrieved documents contain adversarial instructions that hijack model execution.',
        likelihood: 3, impact: 3,
        mitigation: 'Isolate untrusted data inside XML delimiter boundaries, employ secondary guardrail models (Llama Guard), and restrict tool execution permissions.'
      },
      {
        stride: 'E',
        title: 'Excessive Agency & Unbounded Function Calling',
        description: 'AI agent tools have unrestricted system access (shell, DB write, email) without human-in-the-loop confirmation.',
        likelihood: 3, impact: 3,
        mitigation: 'Require explicit human approval for destructive tools; enforce read-only scopes by default.'
      },
      {
        stride: 'I',
        title: 'System Prompt & Secret Exfiltration',
        description: 'Adversarial jailbreaks manipulate the model into disclosing internal system prompts, API keys, or embedded RAG context.',
        likelihood: 2, impact: 2,
        mitigation: 'Sanitize RAG retrieval contexts; never put static API keys or master credentials in system prompt instructions.'
      }
    ],
    abuseCases: [
      {
        title: 'Autonomous Data Exfiltration via Prompt Injection',
        actor: 'Untrusted Document Author',
        scenario: 'Attacker places hidden prompt injection instructions in an uploaded resume. When the AI agent parses it, the agent reads user data and calls an outbound webhook.'
      }
    ]
  }
};

// Global state
const state = {
  projectName: 'Payments Gateway',
  projectDescription: 'Multi-tenant payments processing service handling credit card transactions and merchant settlement via external banking APIs.',
  projectIdea: 'Must meet PCI-DSS Level 1 requirements. Mutual TLS between internal microservices. Data encrypted at rest using KMS keys.',
  components: ['frontend', 'api', 'microservice', 'database', 'storage', 'auth'],
  diagramBase64: null,

  threats: [],
  attackTree: '',
  abuseCases: [],
  controls: [],

  apiProvider: 'nvidia',
  apiModel: 'meta/llama-3.3-70b-instruct',
  apiBaseUrl: 'https://integrate.api.nvidia.com/v1',
  apiKey: '',

  activeTab: 'stride',
  strideFilter: 'all',
  severityFilter: 'all',
  searchQuery: ''
};

// Terminal Logger
function logToTerminal(message, type = 'info') {
  const container = document.getElementById('consoleLogs');
  if (!container) return;

  const timestamp = new Date().toISOString().substring(11, 19);
  const line = document.createElement('div');
  line.className = `log-${type}`;
  line.textContent = `[${timestamp}] ${message}`;

  container.appendChild(line);
  container.scrollTop = container.scrollHeight;
}

// Severity calculator
function calculateSeverity(riskScore) {
  if (riskScore >= 8) return 'critical';
  if (riskScore >= 6) return 'high';
  if (riskScore >= 4) return 'medium';
  return 'low';
}

// App Initialization
document.addEventListener('DOMContentLoaded', () => {
  loadSavedSettings();
  setupComponentChips();
  setupPresets();
  updateProviderIndicator();
  setupEventListeners();
  setupMermaid();

  logToTerminal('ThreatMind Security Workbench ready.', 'success');
  logToTerminal(`Inference Engine: ${state.apiKey ? PROVIDER_CONFIGS[state.apiProvider]?.name : 'Offline Heuristics'}`, 'info');
});

function setupMermaid() {
  if (window.mermaid) {
    mermaid.initialize({
      startOnLoad: false,
      theme: 'dark',
      themeVariables: {
        darkMode: true,
        background: '#121215',
        primaryColor: '#18181b',
        primaryTextColor: '#fafafa',
        primaryBorderColor: '#3f3f46',
        lineColor: '#71717a',
        secondaryColor: '#18181b',
        tertiaryColor: '#121215'
      }
    });
  }
}

function loadSavedSettings() {
  const savedProvider = localStorage.getItem('tm_api_provider');
  const savedModel = localStorage.getItem('tm_api_model');
  const savedBaseUrl = localStorage.getItem('tm_api_base_url');
  const savedKey = localStorage.getItem('tm_api_key');

  if (savedProvider && PROVIDER_CONFIGS[savedProvider]) {
    state.apiProvider = savedProvider;
    state.apiModel = savedModel || PROVIDER_CONFIGS[savedProvider].defaultModel;
    state.apiBaseUrl = savedBaseUrl || PROVIDER_CONFIGS[savedProvider].baseUrl;
  }
  if (savedKey) {
    state.apiKey = savedKey;
  }
}

function updateProviderIndicator() {
  const indicator = document.getElementById('activeEngineText');
  const dot = document.getElementById('statusDot');
  if (!indicator || !dot) return;

  if (state.apiKey) {
    const p = PROVIDER_CONFIGS[state.apiProvider];
    indicator.textContent = `${p?.name || state.apiProvider} (${state.apiModel})`;
    dot.style.background = 'var(--text-primary)';
  } else {
    indicator.textContent = 'Offline Heuristics Engine';
    dot.style.background = 'var(--severity-low)';
  }
}

// Setup Architecture Presets
function setupPresets() {
  document.querySelectorAll('[data-preset]').forEach(btn => {
    btn.addEventListener('click', () => {
      const presetKey = btn.getAttribute('data-preset');
      const preset = ARCHITECTURE_PRESETS[presetKey];
      if (!preset) return;

      document.getElementById('projectName').value = preset.name;
      document.getElementById('projectDesc').value = preset.desc;
      document.getElementById('projectIdea').value = preset.constraints;

      state.projectName = preset.name;
      state.projectDescription = preset.desc;
      state.projectIdea = preset.constraints;
      state.components = [...preset.components];

      syncComponentChips();
      logToTerminal(`Loaded template preset: ${preset.name}`, 'info');
    });
  });
}

// Setup Interactive Component Chips
function setupComponentChips() {
  const chips = document.querySelectorAll('.comp-toggle-chip');
  chips.forEach(chip => {
    chip.addEventListener('click', () => {
      const compKey = chip.getAttribute('data-comp');
      if (state.components.includes(compKey)) {
        state.components = state.components.filter(c => c !== compKey);
        chip.classList.remove('active');
      } else {
        state.components.push(compKey);
        chip.classList.add('active');
      }
      updateCompCountBadge();
    });
  });
  syncComponentChips();
}

function syncComponentChips() {
  document.querySelectorAll('.comp-toggle-chip').forEach(chip => {
    const compKey = chip.getAttribute('data-comp');
    if (state.components.includes(compKey)) {
      chip.classList.add('active');
    } else {
      chip.classList.remove('active');
    }
  });
  updateCompCountBadge();
}

function updateCompCountBadge() {
  const badge = document.getElementById('compCountBadge');
  if (badge) {
    badge.textContent = `${state.components.length} Selected`;
  }
}

function updateMetricsBanner() {
  const totalEl = document.getElementById('metricTotalThreats');
  const critHighEl = document.getElementById('metricCritHigh');
  const controlsEl = document.getElementById('metricControls');
  const compEl = document.getElementById('metricComponents');

  const total = state.threats.length;
  const critHigh = state.threats.filter(t => {
    const sev = calculateSeverity(t.riskScore);
    return sev === 'critical' || sev === 'high';
  }).length;

  const implemented = state.controls.filter(c => c.checked).length;
  const totalControls = state.controls.length;
  const pct = totalControls > 0 ? Math.round((implemented / totalControls) * 100) : 0;

  if (totalEl) totalEl.textContent = total;
  if (critHighEl) critHighEl.textContent = critHigh;
  if (controlsEl) controlsEl.textContent = `${pct}%`;
  if (compEl) compEl.textContent = state.components.length;
}

function setupEventListeners() {
  // Diagram Upload
  const uploadZone = document.getElementById('uploadZone');
  const architectureFile = document.getElementById('architectureFile');
  const previewContainer = document.getElementById('previewContainer');
  const previewImg = document.getElementById('previewImg');
  const btnRemovePreview = document.getElementById('btnRemovePreview');
  const uploadText = document.getElementById('uploadText');

  if (uploadZone && architectureFile) {
    uploadZone.addEventListener('click', (e) => {
      if (e.target !== btnRemovePreview) architectureFile.click();
    });

    architectureFile.addEventListener('change', (e) => {
      const file = e.target.files[0];
      if (file) {
        const reader = new FileReader();
        reader.onload = (evt) => {
          state.diagramBase64 = evt.target.result;
          previewImg.src = evt.target.result;
          previewContainer.style.display = 'block';
          uploadText.style.display = 'none';
          logToTerminal(`Ingested architecture diagram: ${file.name} (${Math.round(file.size / 1024)} KB)`, 'info');
        };
        reader.readAsDataURL(file);
      }
    });

    btnRemovePreview.addEventListener('click', (e) => {
      e.stopPropagation();
      state.diagramBase64 = null;
      architectureFile.value = '';
      previewContainer.style.display = 'none';
      uploadText.style.display = 'block';
    });
  }

  // Settings Modal
  const btnSettings = document.getElementById('btnSettings');
  const settingsModal = document.getElementById('settingsModal');
  const modalClose = document.getElementById('modalClose');
  const settingsForm = document.getElementById('settingsForm');
  const apiProviderSelect = document.getElementById('apiProvider');
  const apiBaseUrlInput = document.getElementById('apiBaseUrl');
  const apiModelInput = document.getElementById('apiModel');
  const apiKeyInput = document.getElementById('apiKey');
  const modelHelpText = document.getElementById('modelHelpText');

  if (btnSettings && settingsModal) {
    btnSettings.addEventListener('click', () => {
      apiProviderSelect.value = state.apiProvider;
      apiBaseUrlInput.value = state.apiBaseUrl;
      apiModelInput.value = state.apiModel;
      apiKeyInput.value = state.apiKey;
      updateModelHelp();
      settingsModal.style.display = 'grid';
    });

    modalClose.addEventListener('click', () => {
      settingsModal.style.display = 'none';
    });

    apiProviderSelect.addEventListener('change', () => {
      const p = PROVIDER_CONFIGS[apiProviderSelect.value];
      if (p) {
        apiBaseUrlInput.value = p.baseUrl;
        apiModelInput.value = p.defaultModel;
        updateModelHelp();
      }
    });

    function updateModelHelp() {
      const p = PROVIDER_CONFIGS[apiProviderSelect.value];
      if (p && modelHelpText) {
        modelHelpText.textContent = p.helpText;
      }
    }

    settingsForm.addEventListener('submit', (e) => {
      e.preventDefault();
      state.apiProvider = apiProviderSelect.value;
      state.apiBaseUrl = apiBaseUrlInput.value.trim();
      state.apiModel = apiModelInput.value.trim();
      state.apiKey = apiKeyInput.value.trim();

      localStorage.setItem('tm_api_provider', state.apiProvider);
      localStorage.setItem('tm_api_base_url', state.apiBaseUrl);
      localStorage.setItem('tm_api_model', state.apiModel);
      localStorage.setItem('tm_api_key', state.apiKey);

      updateProviderIndicator();
      settingsModal.style.display = 'none';
      logToTerminal(`Saved settings for ${state.apiProvider} (${state.apiModel})`, 'success');
    });
  }

  // Custom Threat Modal
  const btnShowAddThreat = document.getElementById('btnShowAddThreatModal');
  const addThreatModal = document.getElementById('addThreatModal');
  const addThreatClose = document.getElementById('addThreatModalClose');
  const addThreatForm = document.getElementById('addThreatForm');

  if (btnShowAddThreat && addThreatModal) {
    btnShowAddThreat.addEventListener('click', () => {
      addThreatModal.style.display = 'grid';
    });

    addThreatClose.addEventListener('click', () => {
      addThreatModal.style.display = 'none';
    });

    addThreatForm.addEventListener('submit', (e) => {
      e.preventDefault();
      const stride = document.getElementById('customStride').value;
      const component = document.getElementById('customComponent').value.trim();
      const title = document.getElementById('customTitle').value.trim();
      const description = document.getElementById('customDesc').value.trim();
      const likelihood = parseInt(document.getElementById('customLikelihood').value, 10);
      const impact = parseInt(document.getElementById('customImpact').value, 10);
      const mitigation = document.getElementById('customMitigation').value.trim();

      const uniqueId = `T-CUSTOM-${Date.now().toString().slice(-4)}`;
      const riskScore = likelihood * impact;

      const newThreat = {
        id: uniqueId,
        stride,
        title,
        description,
        component,
        likelihood,
        impact,
        riskScore,
        mitigation
      };

      state.threats.unshift(newThreat);
      state.controls.push({
        title: `Mitigate ${title}`,
        description: mitigation,
        checked: false,
        threatMap: uniqueId
      });

      addThreatModal.style.display = 'none';
      addThreatForm.reset();
      updateMetricsBanner();
      renderActiveTab();
      logToTerminal(`Recorded custom threat vector: ${title} (${uniqueId})`, 'info');
    });
  }

  // Tabs Navigation
  document.querySelectorAll('.tab').forEach(tabBtn => {
    tabBtn.addEventListener('click', () => {
      document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
      tabBtn.classList.add('active');
      state.activeTab = tabBtn.getAttribute('data-tab');
      renderActiveTab();
    });
  });

  // Filter Buttons
  document.querySelectorAll('[data-filter-stride]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-filter-stride]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.strideFilter = btn.getAttribute('data-filter-stride');
      renderActiveTab();
    });
  });

  document.querySelectorAll('[data-filter-severity]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.querySelectorAll('[data-filter-severity]').forEach(b => b.classList.remove('active'));
      btn.classList.add('active');
      state.severityFilter = btn.getAttribute('data-filter-severity');
      renderActiveTab();
    });
  });

  // Threat search
  const threatSearchInput = document.getElementById('threatSearchInput');
  if (threatSearchInput) {
    threatSearchInput.addEventListener('input', (e) => {
      state.searchQuery = e.target.value.trim().toLowerCase();
      renderActiveTab();
    });
  }

  // Export Dropdown
  const btnExportToggle = document.getElementById('btnExportToggle');
  const exportMenu = document.getElementById('exportMenu');
  if (btnExportToggle && exportMenu) {
    btnExportToggle.addEventListener('click', (e) => {
      e.stopPropagation();
      exportMenu.style.display = exportMenu.style.display === 'block' ? 'none' : 'block';
    });

    document.addEventListener('click', () => {
      exportMenu.style.display = 'none';
    });

    document.getElementById('exportMarkdown')?.addEventListener('click', () => exportReport('markdown'));
    document.getElementById('exportJSON')?.addEventListener('click', () => exportReport('json'));
    document.getElementById('exportCSV')?.addEventListener('click', () => exportReport('csv'));
  }

  // Run Threat Analysis Button
  const btnGenerate = document.getElementById('btnGenerate');
  if (btnGenerate) {
    btnGenerate.addEventListener('click', runThreatAnalysis);
  }
}

// Execution Pipeline
async function runThreatAnalysis() {
  const btnGenerate = document.getElementById('btnGenerate');
  const projectNameInput = document.getElementById('projectName');
  const projectDescInput = document.getElementById('projectDesc');
  const projectIdeaInput = document.getElementById('projectIdea');

  state.projectName = projectNameInput.value.trim() || 'Untitled System';
  state.projectDescription = projectDescInput.value.trim();
  state.projectIdea = projectIdeaInput.value.trim();

  if (state.components.length === 0) {
    logToTerminal('Please select at least one component to evaluate.', 'warning');
    return;
  }

  btnGenerate.disabled = true;
  btnGenerate.textContent = 'Analyzing System Architecture...';
  logToTerminal(`Beginning threat model synthesis for "${state.projectName}"...`, 'info');

  try {
    if (state.apiKey) {
      await generateThreatModelWithAI();
    } else {
      generateThreatModelOffline();
    }

    document.getElementById('welcomeScreen').style.display = 'none';
    document.getElementById('dashboardOutput').style.display = 'block';
    document.getElementById('btnShowAddThreatModal').style.display = 'inline-flex';
    document.getElementById('exportDropdown').style.display = 'inline-block';

    updateMetricsBanner();
    renderActiveTab();
    logToTerminal(`Analysis completed: ${state.threats.length} threats, ${state.abuseCases.length} abuse cases, ${state.controls.length} controls.`, 'success');
  } catch (error) {
    logToTerminal(`Threat analysis failed: ${error.message}`, 'error');
    console.error(error);
  } finally {
    btnGenerate.disabled = false;
    btnGenerate.textContent = 'Run Threat Analysis';
  }
}

// Offline Heuristic Generator
function generateThreatModelOffline() {
  logToTerminal('Executing offline heuristic rules engine.', 'info');
  state.threats = [];
  state.abuseCases = [];
  state.controls = [];

  state.components.forEach(compKey => {
    const compData = HEURISTICS[compKey];
    if (!compData) return;

    compData.threats.forEach((t, idx) => {
      const uniqueId = `T-${compKey.toUpperCase()}-${idx + 1}`;
      const riskScore = t.likelihood * t.impact;

      state.threats.push({
        id: uniqueId,
        stride: t.stride,
        title: t.title,
        description: t.description,
        component: compData.name,
        likelihood: t.likelihood,
        impact: t.impact,
        riskScore: riskScore,
        mitigation: t.mitigation
      });

      state.controls.push({
        title: `Mitigate ${t.title}`,
        description: t.mitigation,
        checked: false,
        threatMap: uniqueId
      });
    });

    compData.abuseCases.forEach(ac => {
      state.abuseCases.push({
        title: ac.title,
        actor: ac.actor,
        scenario: ac.scenario
      });
    });
  });

  state.attackTree = generateMermaidTree();
}

// Attack Tree Generator (Clean dark monochrome theme)
function generateMermaidTree() {
  let tree = 'graph TD\n';
  tree += `  Target["Compromise ${state.projectName}"]\n`;

  state.components.forEach(compKey => {
    const compData = HEURISTICS[compKey];
    if (!compData) return;

    const compNodeId = compKey.toUpperCase();
    tree += `  Target --> ${compNodeId}["${compData.name}"]\n`;

    const threats = compData.threats.slice(0, 2);
    threats.forEach((t, idx) => {
      const threatNodeId = `${compNodeId}_T${idx}`;
      tree += `  ${compNodeId} --> ${threatNodeId}["[${t.stride}] ${t.title}"]\n`;
    });
  });

  return tree;
}

// AI Generation (NVIDIA NIM / Groq / OpenRouter / Gemini / OpenAI / Ollama)
async function generateThreatModelWithAI() {
  const provider = state.apiProvider;
  const config = PROVIDER_CONFIGS[provider] || PROVIDER_CONFIGS.custom;
  const componentNames = state.components.map(c => HEURISTICS[c]?.name || c).join(', ');

  logToTerminal(`Connecting to ${config.name} (${state.apiModel})...`, 'info');

  const systemInstruction = `You are a Principal Security Architect and Threat Modeling Expert.
Generate an exhaustive STRIDE threat model, hierarchical Mermaid.js attack tree, adversary abuse scenarios, and verifiable security controls.

Target Project: ${state.projectName}
System Overview: ${state.projectDescription}
Components: ${componentNames}
Compliance & Constraints: ${state.projectIdea}

You must return ONLY a single valid JSON object with no markdown backticks, no commentary, and no trailing text.
JSON Schema:
{
  "threats": [
    {
      "id": "T-01",
      "stride": "S" | "T" | "R" | "I" | "D" | "E",
      "title": "Clear Threat Vector Title",
      "description": "Technical description of vulnerability and asset at risk",
      "component": "Component Name",
      "likelihood": 1, 2, or 3,
      "impact": 1, 2, or 3,
      "riskScore": likelihood * impact,
      "mitigation": "Prescriptive technical remediation"
    }
  ],
  "attackTree": "graph TD\\n  Root[\\\"Compromise System\\\"] --> NodeA[\\\"...\\\"]",
  "abuseCases": [
    {
      "title": "Abuse Case Title",
      "actor": "Threat Actor Profile",
      "scenario": "Step-by-step adversary execution mechanics"
    }
  ],
  "controls": [
    {
      "title": "Control Title",
      "description": "Verification acceptance criteria",
      "threatMap": "T-01"
    }
  ]
}`;

  let rawOutput = '';

  if (provider === 'gemini') {
    const url = `${state.apiBaseUrl}/v1beta/models/${state.apiModel}:generateContent?key=${state.apiKey}`;
    const parts = [{ text: systemInstruction }];

    if (state.diagramBase64) {
      const match = state.diagramBase64.match(/^data:(.+);base64,(.+)$/);
      if (match) {
        parts.push({
          inlineData: {
            mimeType: match[1],
            data: match[2]
          }
        });
        logToTerminal('Transmitting architecture diagram for multimodal evaluation.', 'info');
      }
    }

    const res = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ contents: [{ parts }] })
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || `Gemini API returned HTTP ${res.status}`);
    }

    const data = await res.json();
    rawOutput = data.candidates?.[0]?.content?.parts?.[0]?.text || '';
  } else {
    // OpenAI-compatible endpoints (NVIDIA NIM, Groq, OpenRouter, OpenAI, Ollama, Custom)
    const url = `${state.apiBaseUrl.replace(/\/+$/, '')}/chat/completions`;

    const headers = {
      'Content-Type': 'application/json'
    };

    if (state.apiKey) {
      headers['Authorization'] = `Bearer ${state.apiKey}`;
    }

    if (provider === 'openrouter') {
      headers['HTTP-Referer'] = 'https://github.com/gvbytes/threatmind-ai';
      headers['X-Title'] = 'ThreatMind AI';
    }

    const userContent = [];
    userContent.push({ type: 'text', text: systemInstruction });

    if (state.diagramBase64 && (state.apiModel.includes('4o') || state.apiModel.includes('vision') || state.apiModel.includes('vl'))) {
      userContent.push({
        type: 'image_url',
        image_url: { url: state.diagramBase64 }
      });
      logToTerminal('Transmitting architecture diagram for vision evaluation.', 'info');
    }

    const bodyPayload = {
      model: state.apiModel,
      messages: [
        {
          role: 'user',
          content: userContent.length === 1 ? systemInstruction : userContent
        }
      ],
      temperature: 0.2
    };

    const res = await fetch(url, {
      method: 'POST',
      headers,
      body: JSON.stringify(bodyPayload)
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({}));
      throw new Error(err?.error?.message || `API Provider returned HTTP ${res.status}`);
    }

    const data = await res.json();
    rawOutput = data.choices?.[0]?.message?.content || '';
  }

  // Extract JSON payload
  const jsonMatch = rawOutput.match(/\{[\s\S]*\}/);
  if (!jsonMatch) {
    throw new Error('AI engine did not return a parseable JSON payload.');
  }

  const parsed = JSON.parse(jsonMatch[0]);

  state.threats = (parsed.threats || []).map((t, idx) => ({
    id: t.id || `T-AI-${idx + 1}`,
    stride: t.stride || 'T',
    title: t.title || 'Untitled Threat',
    description: t.description || '',
    component: t.component || 'System',
    likelihood: parseInt(t.likelihood, 10) || 2,
    impact: parseInt(t.impact, 10) || 2,
    riskScore: (parseInt(t.likelihood, 10) || 2) * (parseInt(t.impact, 10) || 2),
    mitigation: t.mitigation || ''
  }));

  state.attackTree = parsed.attackTree || generateMermaidTree();
  state.abuseCases = parsed.abuseCases || [];
  state.controls = (parsed.controls || []).map(c => ({
    title: c.title || 'Mitigation Control',
    description: c.description || '',
    checked: false,
    threatMap: c.threatMap || ''
  }));
}

// Render Active Tab Content
function renderActiveTab() {
  const container = document.getElementById('tabContent');
  const filtersContainer = document.getElementById('tabFilters');
  if (!container) return;

  if (filtersContainer) {
    filtersContainer.style.display = state.activeTab === 'stride' ? 'flex' : 'none';
  }

  container.innerHTML = '';

  switch (state.activeTab) {
    case 'stride':
      renderStrideTab(container);
      break;
    case 'tree':
      renderAttackTreeTab(container);
      break;
    case 'abuse':
      renderAbuseCasesTab(container);
      break;
    case 'risk':
      renderRiskScorecardTab(container);
      break;
    case 'controls':
      renderSecurityControlsTab(container);
      break;
  }
}

// Tab: STRIDE Threats
function renderStrideTab(container) {
  let filtered = state.threats;

  if (state.strideFilter !== 'all') {
    filtered = filtered.filter(t => t.stride.toUpperCase() === state.strideFilter.toUpperCase());
  }

  if (state.severityFilter !== 'all') {
    filtered = filtered.filter(t => calculateSeverity(t.riskScore) === state.severityFilter);
  }

  if (state.searchQuery) {
    filtered = filtered.filter(t => 
      t.title.toLowerCase().includes(state.searchQuery) ||
      t.description.toLowerCase().includes(state.searchQuery) ||
      t.mitigation.toLowerCase().includes(state.searchQuery) ||
      t.component.toLowerCase().includes(state.searchQuery)
    );
  }

  if (filtered.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 2.5rem; color: var(--text-muted); font-size: 0.82rem;">
        No threats matching current filter criteria.
      </div>
    `;
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'threat-grid';

  filtered.forEach(threat => {
    const sev = calculateSeverity(threat.riskScore);
    const item = document.createElement('div');
    item.className = `threat-item severity-${sev}`;
    item.innerHTML = `
      <div class="threat-header">
        <div class="threat-badges">
          <span class="badge-stride">${threat.stride} - ${STRIDE_NAMES[threat.stride] || 'STRIDE'}</span>
          <span class="badge-severity badge-${sev}">${sev}</span>
          <span class="threat-id">${threat.id}</span>
        </div>
        <span style="font-size: 0.72rem; color: var(--text-faint); font-family: var(--font-mono);">${threat.component}</span>
      </div>
      <div class="threat-title" contenteditable="true" data-field="title" data-id="${threat.id}">${escapeHtml(threat.title)}</div>
      <div class="threat-desc" contenteditable="true" data-field="description" data-id="${threat.id}">${escapeHtml(threat.description)}</div>
      <div class="threat-mitigation">
        <strong style="color: var(--text-primary); margin-right: 0.25rem;">Mitigation:</strong>
        <span contenteditable="true" data-field="mitigation" data-id="${threat.id}">${escapeHtml(threat.mitigation)}</span>
      </div>
      <div class="threat-meta-row">
        <span>Likelihood: ${threat.likelihood}/3</span>
        <span>Impact: ${threat.impact}/3</span>
        <span>Risk Score: <strong>${threat.riskScore}/9</strong></span>
      </div>
    `;

    // Inline edit handlers
    item.querySelectorAll('[contenteditable="true"]').forEach(el => {
      el.addEventListener('blur', (e) => {
        const field = e.target.getAttribute('data-field');
        const threatId = e.target.getAttribute('data-id');
        const targetThreat = state.threats.find(t => t.id === threatId);
        if (targetThreat) {
          targetThreat[field] = e.target.textContent.trim();
        }
      });
    });

    grid.appendChild(item);
  });

  container.appendChild(grid);
}

// Tab: Attack Tree
function renderAttackTreeTab(container) {
  const wrapper = document.createElement('div');
  wrapper.className = 'mermaid-wrapper';

  const graphDiv = document.createElement('div');
  graphDiv.className = 'mermaid';
  graphDiv.textContent = state.attackTree;

  wrapper.appendChild(graphDiv);
  container.appendChild(wrapper);

  if (window.mermaid) {
    try {
      mermaid.run({ nodes: [graphDiv] });
    } catch (e) {
      console.warn('Mermaid render error:', e);
      graphDiv.innerHTML = `<pre style="font-family: var(--font-mono); font-size: 0.75rem; color: var(--text-muted);">${escapeHtml(state.attackTree)}</pre>`;
    }
  }
}

// Tab: Abuse Cases
function renderAbuseCasesTab(container) {
  if (state.abuseCases.length === 0) {
    container.innerHTML = `
      <div style="text-align: center; padding: 2.5rem; color: var(--text-muted); font-size: 0.82rem;">
        No adversary abuse cases registered.
      </div>
    `;
    return;
  }

  const grid = document.createElement('div');
  grid.className = 'threat-grid';

  state.abuseCases.forEach((ac, idx) => {
    const card = document.createElement('div');
    card.className = 'threat-item';
    card.innerHTML = `
      <div class="threat-header">
        <div class="threat-badges">
          <span class="badge-stride">SCENARIO #${idx + 1}</span>
        </div>
        <span style="font-size: 0.72rem; color: var(--text-faint); font-family: var(--font-mono);">Actor: ${escapeHtml(ac.actor)}</span>
      </div>
      <div class="threat-title">${escapeHtml(ac.title)}</div>
      <div class="threat-desc">${escapeHtml(ac.scenario)}</div>
    `;
    grid.appendChild(card);
  });

  container.appendChild(grid);
}

// Tab: Risk Scorecard
function renderRiskScorecardTab(container) {
  const criticalCount = state.threats.filter(t => calculateSeverity(t.riskScore) === 'critical').length;
  const highCount = state.threats.filter(t => calculateSeverity(t.riskScore) === 'high').length;
  const mediumCount = state.threats.filter(t => calculateSeverity(t.riskScore) === 'medium').length;
  const lowCount = state.threats.filter(t => calculateSeverity(t.riskScore) === 'low').length;

  const card = document.createElement('div');
  card.className = 'card';
  card.innerHTML = `
    <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 0.75rem; margin-bottom: 1.5rem; text-align: center;">
      <div style="background: var(--severity-critical-bg); border: 1px solid var(--severity-critical-border); padding: 1rem; border-radius: var(--radius-sm);">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--severity-critical); font-family: var(--font-mono);">${criticalCount}</div>
        <div style="font-size: 0.7rem; font-weight: 600; text-transform: uppercase; color: var(--severity-critical); margin-top: 0.2rem;">Critical</div>
      </div>
      <div style="background: var(--severity-high-bg); border: 1px solid var(--severity-high-border); padding: 1rem; border-radius: var(--radius-sm);">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--severity-high); font-family: var(--font-mono);">${highCount}</div>
        <div style="font-size: 0.7rem; font-weight: 600; text-transform: uppercase; color: var(--severity-high); margin-top: 0.2rem;">High</div>
      </div>
      <div style="background: var(--severity-medium-bg); border: 1px solid var(--severity-medium-border); padding: 1rem; border-radius: var(--radius-sm);">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--severity-medium); font-family: var(--font-mono);">${mediumCount}</div>
        <div style="font-size: 0.7rem; font-weight: 600; text-transform: uppercase; color: var(--severity-medium); margin-top: 0.2rem;">Medium</div>
      </div>
      <div style="background: var(--severity-low-bg); border: 1px solid var(--severity-low-border); padding: 1rem; border-radius: var(--radius-sm);">
        <div style="font-size: 1.5rem; font-weight: 700; color: var(--severity-low); font-family: var(--font-mono);">${lowCount}</div>
        <div style="font-size: 0.7rem; font-weight: 600; text-transform: uppercase; color: var(--severity-low); margin-top: 0.2rem;">Low</div>
      </div>
    </div>

    <div style="font-size: 0.82rem; font-weight: 600; margin-bottom: 0.75rem; text-transform: uppercase; color: var(--text-muted); letter-spacing: 0.5px;">Highest Impact Threat Vectors</div>
    <div class="threat-grid">
      ${state.threats.slice(0, 5).sort((a, b) => b.riskScore - a.riskScore).map(t => `
        <div class="threat-item severity-${calculateSeverity(t.riskScore)}">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <strong>${escapeHtml(t.title)}</strong>
            <span class="badge-severity badge-${calculateSeverity(t.riskScore)}">Score: ${t.riskScore}/9</span>
          </div>
          <div style="font-size: 0.78rem; color: var(--text-muted); margin-top: 0.25rem;">${escapeHtml(t.mitigation)}</div>
        </div>
      `).join('')}
    </div>
  `;

  container.appendChild(card);
}

// Tab: Security Controls Checklist
function renderSecurityControlsTab(container) {
  const implementedCount = state.controls.filter(c => c.checked).length;
  const totalCount = state.controls.length;
  const pct = totalCount > 0 ? Math.round((implementedCount / totalCount) * 100) : 0;

  const summary = document.createElement('div');
  summary.style.marginBottom = '1rem';
  summary.innerHTML = `
    <div style="display: flex; justify-content: space-between; align-items: center; margin-bottom: 0.4rem; font-size: 0.78rem;">
      <span style="color: var(--text-secondary);">Mitigation Implementation Progress</span>
      <span style="font-family: var(--font-mono);">${implementedCount} / ${totalCount} (${pct}%)</span>
    </div>
    <div style="background: var(--bg-surface-elevated); height: 6px; border-radius: 3px; overflow: hidden; border: 1px solid var(--border-subtle);">
      <div style="background: var(--severity-low); height: 100%; width: ${pct}%; transition: width 0.2s;"></div>
    </div>
  `;
  container.appendChild(summary);

  state.controls.forEach((ctrl, idx) => {
    const item = document.createElement('div');
    item.className = 'control-item';
    item.innerHTML = `
      <input type="checkbox" id="ctrl_${idx}" ${ctrl.checked ? 'checked' : ''}>
      <div class="control-content">
        <label for="ctrl_${idx}" class="control-title" style="cursor: pointer;">${escapeHtml(ctrl.title)}</label>
        <div class="control-desc">${escapeHtml(ctrl.description)}</div>
      </div>
    `;

    item.querySelector('input').addEventListener('change', (e) => {
      ctrl.checked = e.target.checked;
      updateMetricsBanner();
      renderSecurityControlsTab(container);
    });

    container.appendChild(item);
  });
}

// Multi-Format Export Engine
function exportReport(format) {
  const filename = `${state.projectName.toLowerCase().replace(/[^a-z0-9]+/g, '-')}-threat-model.${format === 'markdown' ? 'md' : format}`;

  let content = '';
  let mimeType = 'text/plain';

  if (format === 'markdown') {
    mimeType = 'text/markdown';
    content = `# Threat Model: ${state.projectName}

**Generated:** ${new Date().toUTCString()}  
**Engine:** ${state.apiKey ? PROVIDER_CONFIGS[state.apiProvider]?.name : 'Offline Heuristics'}  

## 1. System Overview
${state.projectDescription || 'No description provided.'}

### Constraints & Security Assumptions
${state.projectIdea || 'None specified.'}

---

## 2. STRIDE Threat Catalog

| ID | STRIDE | Component | Threat Title | Likelihood | Impact | Score | Mitigation |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- | :--- |
${state.threats.map(t => `| **${t.id}** | ${t.stride} (${STRIDE_NAMES[t.stride] || ''}) | ${t.component} | ${t.title} | ${t.likelihood}/3 | ${t.impact}/3 | **${t.riskScore}/9** | ${t.mitigation} |`).join('\n')}

---

## 3. Attack Tree

\`\`\`mermaid
${state.attackTree}
\`\`\`

---

## 4. Adversary Abuse Scenarios

${state.abuseCases.map((ac, idx) => `### Abuse Scenario ${idx + 1}: ${ac.title}
- **Adversary Actor:** ${ac.actor}
- **Attack Path:** ${ac.scenario}
`).join('\n')}

---

## 5. Security Controls Checklist

${state.controls.map(c => `- [${c.checked ? 'x' : ' '}] **${c.title}**: ${c.description}`).join('\n')}
`;
  } else if (format === 'json') {
    mimeType = 'application/json';
    content = JSON.stringify({
      projectName: state.projectName,
      generatedAt: new Date().toISOString(),
      engine: state.apiKey ? state.apiProvider : 'offline_heuristics',
      components: state.components,
      threats: state.threats,
      attackTree: state.attackTree,
      abuseCases: state.abuseCases,
      controls: state.controls
    }, null, 2);
  } else if (format === 'csv') {
    mimeType = 'text/csv';
    const rows = [
      ['ID', 'STRIDE', 'Component', 'Title', 'Description', 'Likelihood', 'Impact', 'RiskScore', 'Mitigation']
    ];
    state.threats.forEach(t => {
      rows.push([
        t.id,
        t.stride,
        t.component,
        `"${t.title.replace(/"/g, '""')}"`,
        `"${t.description.replace(/"/g, '""')}"`,
        t.likelihood,
        t.impact,
        t.riskScore,
        `"${t.mitigation.replace(/"/g, '""')}"`
      ]);
    });
    content = rows.map(r => r.join(',')).join('\n');
  }

  const blob = new Blob([content], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename;
  document.body.appendChild(a);
  a.click();
  document.body.removeChild(a);
  URL.revokeObjectURL(url);

  logToTerminal(`Exported threat report to ${filename}`, 'success');
}

function escapeHtml(str) {
  if (!str) return '';
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}