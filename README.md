# ThreatMind AI

A developer-first security threat modeling and STRIDE analysis workbench.

Threat modeling is frequently neglected because legacy enterprise tools are cumbersome, siloed, and disconnected from modern software architectures. **ThreatMind AI** provides a fast, browser-based workspace to evaluate application architectures, synthesize hierarchical attack trees, model adversary abuse scenarios, and generate verifiable mitigation checklists.

It runs completely client-side and supports **NVIDIA NIM**, **Groq**, **OpenRouter**, **Google Gemini**, **OpenAI**, and **Local Ollama**—with a built-in offline heuristics engine that requires no API keys or backend setup.

---

## Key Capabilities

- **Multi-Provider AI Engine:** Connect directly to free and open inference providers:
  - **NVIDIA NIM:** High-performance inference on `meta/llama-3.3-70b-instruct` and `deepseek-ai/deepseek-r1` using free credits from [build.nvidia.com](https://build.nvidia.com).
  - **Groq Cloud:** Ultra-low latency inference on `llama-3.3-70b-versatile` with a generous free tier.
  - **OpenRouter:** Free model access via `meta-llama/llama-3.3-70b-instruct:free`.
  - **Google Gemini:** Direct integration with Gemini 1.5/2.0 Flash models, including multimodal architecture diagram inspection.
  - **Ollama (100% Private):** Run completely offline against local models (`llama3.3`, `mistral`, `deepseek-r1`) for sensitive enterprise architectures that cannot leave your infrastructure.
  - **Offline Heuristics:** Zero-dependency, offline rule engine covering 11 core infrastructure components without requiring an API key.
- **Multimodal Diagram Analysis:** Upload system architecture diagrams (PNG, JPG, SVG) for automated component extraction and data flow analysis.
- **Hierarchical Attack Trees:** Renders dynamic adversary compromise paths natively in dark-themed Mermaid.js syntax.
- **Modern Infrastructure Coverage:** Pre-configured security threat profiles for Web SPAs, Mobile Clients, API Gateways, Microservices, Relational DBs, NoSQL, In-Memory Caches, Cloud Object Storage (S3), OAuth2/OIDC Identity Providers, Message Brokers (Kafka), and **LLM / AI Agent Orchestrators (OWASP Top 10 for LLMs)**.
- **DevSecOps Export:** Export complete threat models to **Markdown** (for documentation and RFCs), structured **JSON** (for CI/CD validation pipelines), or **CSV** (for risk registers).
- **Privacy-First:** Pure client-side static application. No telemetry, no external databases, and API keys remain strictly in browser `localStorage`.

---

## Supported Threat Modeling Methodology

ThreatMind AI implements the **STRIDE** threat categorization model combined with qualitative risk scoring (Likelihood × Impact):

| Category | Security Property Violated | Definition | Example Risk |
| :--- | :--- | :--- | :--- |
| **S - Spoofing** | Authenticity | Pretending to be an authorized user or internal service. | Stolen JWT, forged service identity, missing mTLS. |
| **T - Tampering** | Integrity | Unauthorized modification of code, data, or network traffic. | SQL/NoSQL injection, prompt injection, cache poisoning. |
| **R - Repudiation** | Non-Repudiation | Inability to prove an adversary performed a specific operation. | Missing tamper-proof audit trails for administrative queries. |
| **I - Information Disclosure** | Confidentiality | Exposing sensitive data to unauthorized parties. | Unrestricted S3 buckets, plaintext cache secrets, PII leaks. |
| **D - Denial of Service** | Availability | Exhausting resources to degrade or prevent system availability. | Rate limit exhaustion, poison pill queue messages, cascading thread starvation. |
| **E - Elevation of Privilege** | Authorization | Gaining unearned access rights or execution privileges. | Broken Object Level Authorization (BOLA/IDOR), unrestricted LLM tool execution. |

---

## Quickstart

### Running Locally
Because ThreatMind AI is a zero-build static application, you can run it directly using any local HTTP server:

```bash
# Clone the repository
git clone https://github.com/gvbytes/threatmind-ai.git
cd threatmind-ai

# Start a local server (Python 3)
python3 -m http.server 8000
```

Open `http://localhost:8000` in your web browser.

---

## Configuring Free AI Providers

Click the **Settings (gear icon)** in the top navigation bar to configure your preferred inference provider:

### 1. NVIDIA NIM (Recommended)
1. Create a free developer account at [build.nvidia.com](https://build.nvidia.com).
2. Generate a personal API key (includes 1,000 free inference credits).
3. Select **NVIDIA NIM** in ThreatMind settings, paste your key, and use the default model `meta/llama-3.3-70b-instruct`.

### 2. Groq Cloud (Fastest Free Tier)
1. Get a free API key at [console.groq.com](https://console.groq.com).
2. Select **Groq Cloud** in settings and use model `llama-3.3-70b-versatile`.

### 3. OpenRouter (Free Community Tier)
1. Sign up at [openrouter.ai](https://openrouter.ai).
2. Create an API key and choose a free model such as `meta-llama/llama-3.3-70b-instruct:free`.

### 4. Ollama (100% Private & Air-Gapped)
For proprietary or classified system designs:
1. Install [Ollama](https://ollama.com) on your machine.
2. Run your preferred model:
   ```bash
   ollama run llama3.3
   ```
3. Set provider to **Ollama** in ThreatMind settings (default URL: `http://localhost:11434/v1`). No API key is required.

### 5. Offline Heuristics
If you leave the API key blank, ThreatMind AI automatically defaults to its built-in rule engine, analyzing your selected components using static threat heuristics without making any outbound network calls.

---

## Threat Model Workflow

1. **Scope Definition:** Enter your application name, architectural overview, and compliance boundaries (e.g. PCI-DSS, SOC 2, HIPAA).
2. **Component Mapping:** Add the technical building blocks representing your infrastructure (API Gateway, PostgreSQL, Redis, S3, AI Agent, etc.).
3. **Diagram Ingestion (Optional):** Attach an architecture diagram to provide visual topology context.
4. **Execute Analysis:** Click **Run Threat Analysis**. The tool synthesizes:
   - Exhaustive STRIDE threat cards with prescriptive technical mitigations.
   - A Mermaid.js attack tree mapping potential adversary compromise paths.
   - Concrete adversary abuse scenarios with threat actor profiles.
   - An interactive security controls checklist with implementation progress tracking.
5. **Review & Edit:** All threat titles, descriptions, and mitigations support inline editing directly in the interface. Click **+ Custom Threat** to record organization-specific vectors.
6. **Export Report:** Export findings to Markdown, JSON, or CSV for team review or ticketing.

---

## Project Structure

```
threatmind-ai/
├── index.html       # Clean, high-density threat modeling UI
├── styles.css       # Slate/charcoal cybersecurity theme (zero neon/purple)
├── app.js           # Multi-provider AI engine, heuristics database, and export logic
├── README.md        # Technical methodology and setup guide
└── LICENSE          # MIT License
```

---

## License

This project is licensed under the [MIT License](LICENSE).
