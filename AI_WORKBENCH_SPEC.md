# AI Workbench Specification

This file turns the CyberNews product brief into an implementable AI feature set.

The important security rule is simple: AI output is helpful, but it is not trusted.
Generated reports should come from structured JSON and render inside safe components
or a sandboxed iframe.

## 1. Goal

Implement an **AI Workbench** inside the CyberNews dashboard.

The AI Workbench should let an analyst right-click dashboard entities, run contextual AI actions, view structured results, generate safe clickable HTML reports, save reports, and iterate on earlier results.

This is not a general chatbot. It is a contextual AI layer attached to threat intelligence objects.

## 2. Core Objects

Supported entity types:

```text
article
advisory
cve
ioc
attack_technique
threat_actor
malware_family
incident
detection_rule
report
```

MVP entity types:

```text
article
cve
ioc
attack_technique
report
```

## 3. Main User Experience

### Right-click Context Menu

Menu title:

```text
AI Actions
```

Menu options:

```text
Summarize
Analyze
Show connections
Generate report
Extract IOCs
Extract CVEs
CVE enrichment
IOC enrichment
MITRE ATT&CK mapping
Severity classification
Generate detection rule
Recommend remediation
```

Each menu item should create an AI job.

### AI Workbench Panel

Panel name:

```text
AI Workbench
```

Tabs:

```text
Result
Report
Evidence
JSON
History
```

The panel should show:

```text
Job status
Selected entity
Generated summary
Extracted entities
Generated relationships
Confidence scores
Evidence snippets
Clickable internal entity links
Actions: Save report, Export HTML, Copy JSON, Create incident, Regenerate
```

## 4. MVP AI Workflows

### Workflow A: Article Analysis

Input:

```text
article
```

Actions:

```text
Summarize
Analyze
Extract IOCs
Extract CVEs
MITRE ATT&CK mapping
Generate report
```

Expected output:

```json
{
  "summary": {
    "executive": "Short non-technical summary",
    "technical": "Technical analyst summary",
    "key_points": []
  },
  "extracted_cves": [],
  "extracted_iocs": [],
  "extracted_entities": {
    "vendors": [],
    "products": [],
    "malware_families": [],
    "threat_actors": []
  },
  "attack_mappings": [],
  "recommended_actions": [],
  "confidence": 0.0,
  "evidence": []
}
```

### Workflow B: CVE Enrichment

Input:

```text
cve
```

Use existing or local data first, then enrich from:

```text
CISA KEV
EPSS
NVD CVE API
GitHub Advisory Database later
```

Expected output:

```json
{
  "cve_id": "CVE-YYYY-NNNN",
  "summary": "",
  "cvss": null,
  "epss": null,
  "kev": {
    "is_known_exploited": false,
    "due_date": null,
    "known_ransomware_use": null
  },
  "affected_products": [],
  "references": [],
  "risk_classification": "low|medium|high|critical",
  "recommended_action": "",
  "reasoning": "",
  "evidence": []
}
```

Important rule:

```text
The LLM may explain risk, but it must not invent CVSS, EPSS, KEV, vendor, or patch data.
These values must come from deterministic sources.
```

### Workflow C: IOC Investigation

Input:

```text
ioc
```

Supported IOC types:

```text
ipv4
ipv6
domain
url
sha256
sha1
md5
email
file_path
registry_key
```

Expected output:

```json
{
  "ioc": "",
  "ioc_type": "",
  "summary": "",
  "first_seen": null,
  "last_seen": null,
  "sightings": [],
  "related_articles": [],
  "related_cves": [],
  "related_malware": [],
  "related_actors": [],
  "recommended_action": "monitor|block|investigate|escalate",
  "confidence": 0.0,
  "evidence": []
}
```

### Workflow D: Show Connections

Input:

```text
any entity
```

Output should include deterministic and AI-inferred connections.

Connection types:

```text
mentions
affects
exploits
observed_in
maps_to
related_to
mitigated_by
detected_by
possibly_related_to
possibly_maps_to
```

Expected output:

```json
{
  "source_entity": {
    "type": "article",
    "id": "article_123",
    "label": "Article title"
  },
  "connections": [
    {
      "target_type": "cve",
      "target_id": "CVE-2025-1234",
      "target_label": "CVE-2025-1234",
      "relationship": "mentions",
      "confidence": 1.0,
      "evidence": ["Exact CVE string found in article"]
    }
  ]
}
```

UI:

```text
Show connections as a small graph and as a table.
Allow analysts to approve or reject inferred relationships.
```

### Workflow E: Generate HTML Report

Input:

```text
article
cve
ioc
incident
selected entity group
```

Do not allow the model to produce arbitrary trusted HTML as the main source of truth.

Safe report flow:

1. AI returns structured report JSON.
2. Frontend renders it into safe HTML components.
3. Render the final report in a sandboxed iframe or controlled component renderer.

Report schema:

```json
{
  "title": "Threat Intelligence Report",
  "subtitle": "",
  "created_at": "",
  "source_entities": [],
  "sections": [
    {
      "type": "summary",
      "heading": "Executive Summary",
      "content": ""
    },
    {
      "type": "bullet_list",
      "heading": "Key Findings",
      "items": []
    },
    {
      "type": "table",
      "heading": "Extracted IOCs",
      "columns": ["Type", "Value", "Confidence", "Source"],
      "rows": []
    },
    {
      "type": "entity_links",
      "heading": "Related Entities",
      "links": [
        {
          "label": "CVE-2025-1234",
          "entity_type": "cve",
          "entity_id": "CVE-2025-1234"
        }
      ]
    },
    {
      "type": "recommendations",
      "heading": "Recommended Actions",
      "items": []
    }
  ]
}
```

Allowed report section types:

```text
summary
paragraph
bullet_list
numbered_list
table
ioc_table
cve_table
attack_mapping_table
entity_links
source_links
flowchart
timeline
recommendations
detection_rule
remediation_plan
```

Dynamic visuals should still come from structured JSON. For example, a `flowchart`
section can contain nodes and edges, and the frontend decides how to render it.
The model should not generate arbitrary trusted HTML for diagrams or source links.

Current implementation supports `source_links` first. Links must use `http://`
or `https://`; `javascript:` and other schemes are not rendered.

## 5. Backend API

Target API shape:

```text
POST /api/ai/jobs
GET  /api/ai/jobs/{job_id}
GET  /api/ai/jobs/{job_id}/stream
POST /api/ai/jobs/{job_id}/feedback
POST /api/ai/jobs/{job_id}/regenerate

GET  /api/entities/{entity_type}/{entity_id}
GET  /api/entities/{entity_type}/{entity_id}/connections

POST /api/reports
GET  /api/reports/{report_id}
POST /api/reports/{report_id}/iterate
GET  /api/reports/{report_id}/export/html

POST /api/detections/generate
POST /api/detections/{rule_id}/review
```

Current Flask MVP can implement the same concepts with simple routes first.

## 6. AI Job Request Schema

```json
{
  "action": "summarize|analyze|extract_iocs|extract_cves|show_connections|generate_report|cve_enrichment|ioc_enrichment|attack_mapping|severity_classification|generate_detection|recommend_remediation",
  "entity_type": "article|advisory|cve|ioc|attack_technique|incident|report",
  "entity_id": "string",
  "selected_text": "optional string",
  "context_depth": "low|medium|high",
  "output_format": "structured_json|html_report|both",
  "analyst_goal": "optional string"
}
```

## 7. AI Job Response Schema

```json
{
  "job_id": "uuid",
  "status": "queued|running|completed|failed",
  "action": "analyze",
  "entity_type": "article",
  "entity_id": "article_123",
  "result_json": {},
  "report_json": null,
  "rendered_html": null,
  "confidence": 0.0,
  "warnings": [],
  "evidence": [],
  "created_at": "",
  "completed_at": null
}
```

## 8. Database Tables

Future tables:

```text
ai_jobs
ai_artifacts
ai_evidence
entity_relations
reports
report_versions
analyst_feedback
detection_rules
```

Suggested `ai_jobs` fields:

```text
id
action
entity_type
entity_id
selected_text
context_depth
output_format
status
model
prompt_version
input_context_hash
result_json
error_message
created_by
created_at
completed_at
```

Suggested `entity_relations` fields:

```text
id
source_type
source_id
target_type
target_id
relationship
confidence
evidence_json
created_by
created_at
status
```

Relation status values:

```text
auto_accepted
needs_review
approved
rejected
```

Suggested `reports` fields:

```text
id
title
source_entities_json
report_json
rendered_html
created_by
created_at
updated_at
```

## 9. Frontend Components

Future React/Next.js components:

```text
AIContextMenu
AIWorkbenchPanel
AIJobStatusBadge
AIResultView
AIReportView
AIEvidenceView
AIJsonView
AIHistoryView
EntityConnectionGraph
EntityConnectionTable
ReportRenderer
ReportToolbar
DetectionRuleCard
```

Minimum UI behavior:

```text
Right-click entity -> context menu opens
Click AI action -> POST /api/ai/jobs
Open AI Workbench automatically
Show loading state
Poll or stream job status
Render result when complete
Allow saving report
Allow copying JSON
Allow approving/rejecting inferred connections
```

## 10. Report Security Requirements

Generated reports must be treated as untrusted content.

Requirements:

```text
Do not directly trust model-generated raw HTML.
Prefer JSON report schema -> safe renderer.
If raw HTML export is needed, sanitize it.
Render preview in sandboxed iframe.
Disallow scripts.
Disallow inline event handlers.
Disallow forms.
Disallow external JavaScript.
Disallow javascript: URLs.
Do not allow generated reports to call privileged dashboard APIs.
```

Suggested iframe:

```html
<iframe
  sandbox="allow-popups"
  referrerpolicy="no-referrer"
></iframe>
```

Do not use:

```text
allow-scripts
allow-same-origin
```

unless absolutely required.

Current MVP decision:

```text
AI returns structured report JSON.
The app renders controlled HTML from that JSON.
The sandboxed iframe previews the rendered report.
PDF export starts as browser Print / Save as PDF from the iframe preview.
```

Raw model-generated HTML is not part of the main MVP path.

## 11. Prompting Strategy

Each AI action should have a versioned prompt template.

Prompt files:

```text
prompts/summarize.md
prompts/analyze_article.md
prompts/extract_iocs.md
prompts/extract_cves.md
prompts/cve_enrichment.md
prompts/ioc_enrichment.md
prompts/attack_mapping.md
prompts/severity_classification.md
prompts/generate_report.md
prompts/generate_detection.md
prompts/recommend_remediation.md
```

Every prompt should enforce:

```text
Return valid JSON only.
Do not invent facts.
Use only provided context.
Separate facts from assumptions.
Include confidence scores.
Include evidence snippets.
Flag missing data.
```

## 12. Detection Rule Generation

Supported first rule formats:

```text
Sigma
YARA
KQL
Splunk SPL
```

Detection rule output schema:

```json
{
  "rule_type": "sigma|yara|kql|splunk",
  "title": "",
  "description": "",
  "detection_goal": "",
  "required_logs": [],
  "rule_content": "",
  "attack_mappings": [],
  "false_positive_notes": [],
  "test_notes": "",
  "confidence": 0.0,
  "warnings": []
}
```

Important:

```text
Generated detection rules are drafts only.
They must be marked as "needs analyst review".
Do not auto-deploy rules.
```

## 13. Severity Classification

Severity should combine deterministic signals and AI explanation.

Inputs:

```text
CVSS
EPSS
CISA KEV status
recency
source frequency
affected product criticality
internal asset exposure if available
```

Output:

```json
{
  "severity": "low|medium|high|critical",
  "priority": "monitor|patch_later|patch_soon|patch_now|escalate",
  "reasoning": "",
  "deterministic_signals": {
    "cvss": null,
    "epss": null,
    "kev": false,
    "source_count": 0
  },
  "assumptions": [],
  "confidence": 0.0
}
```

Rule:

```text
The AI explains the classification but does not fabricate source data.
```

## 14. MVP Implementation Order

Implement in this order:

```text
1. AI job database model
2. POST /api/ai/jobs
3. Basic Gemini structured-output service
4. AI Workbench frontend panel
5. Right-click AIContextMenu
6. Article summarization
7. IOC extraction
8. CVE extraction
9. CVE enrichment using existing KEV/EPSS data
10. Report JSON schema
11. Safe ReportRenderer
12. Save report
13. Simple print-to-PDF export
14. Entity connections table
15. MITRE ATT&CK candidate mapping
16. Detection rule draft generation
```

## 15. Acceptance Criteria

The MVP is complete when:

```text
An analyst can right-click an article and run "Analyze".
The AI Workbench opens and shows job status.
The backend creates an ai_jobs record.
The AI returns structured JSON.
The UI displays summary, extracted CVEs, extracted IOCs, evidence, and confidence.
The analyst can generate a report from the article.
The report is rendered as safe clickable HTML.
The report links back to dashboard entities.
The analyst can save the report.
The analyst can print/save the report preview as PDF.
The analyst can view raw JSON.
The system does not trust arbitrary raw AI-generated HTML.
```

## 16. Non-Goals For MVP

Do not implement these yet:

```text
Autonomous remediation
Automatic blocking of IOCs
Automatic deployment of detection rules
Full incident case management
Full graph database migration
Full STIX/TAXII implementation
Multi-agent workflows
Backend PDF generation
```

## 17. Design Principle

Use AI for:

```text
summarization
extraction
explanation
candidate relationship generation
report drafting
detection draft generation
remediation draft generation
```

Do not use AI as the source of truth for:

```text
EPSS score
CISA KEV status
CVSS score
NVD vendor/product data
IOC reputation
patch availability
whether a detection rule is production-safe
```

Those must come from deterministic APIs, local database records, or analyst review.
