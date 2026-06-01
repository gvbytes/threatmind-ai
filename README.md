# ThreatMind AI - Visual Threat Modeling Workspace

Warning: This tool is currently in research and development. It uses external APIs (Gemini or OpenAI) from the browser to generate threat models, which might occasionally fail or show errors depending on your API key or network. If you get errors, leave the API key blank to use the built-in offline rules (Heuristic Mode).

## What is this?
I created ThreatMind AI to help developers and students analyze the security of their application architectures. You can map out components, check for STRIDE threats, and build simple attack trees without setting up complex backend environments or dependencies.

## Features
- STRIDE categorization (Spoofing, Tampering, Repudiation, Information Disclosure, Denial of Service, Elevation of Privilege)
- Attack tree rendering via Mermaid.js
- Local heuristics option to run offline without an API key
- Inline editing (double-click any text field in the threat list to change it)
- Export to Markdown file

## Tech Stack
- HTML5 and CSS (Vanilla styles)
- JavaScript (No build steps required)
- Mermaid.js (loaded via CDN)

## How to Use

1. Open index.html in any modern web browser.
2. In the sidebar, fill in your Project Name and Description.
3. Add system components (like Web Frontend, Backend API, Database) using the Architecture Nodes selector.
4. If you want to use the offline rules, leave the API key field blank. If you want to use AI analysis, click the settings gear icon, enter your API key, and select a model.
5. Click "Generate Threat Model".
6. Double-click any field to make edits, or click "Add Custom Threat" to append new items.
7. Click "Export Report" to save it as a Markdown file.
