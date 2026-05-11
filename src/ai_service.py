import json
import os

try:
    from google import genai
    from google.genai import types
except ImportError:
    genai = None
    types = None


ARTICLE_ANALYSIS_SCHEMA = {
    "type": "object",
    "properties": {
        "summary": {
            "type": "object",
            "properties": {
                "executive": {"type": "string"},
                "technical": {"type": "string"},
                "key_points": {
                    "type": "array",
                    "items": {"type": "string"},
                },
            },
            "required": ["executive", "technical", "key_points"],
        },
        "extracted_cves": {
            "type": "array",
            "items": {"type": "string"},
        },
        "extracted_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "value": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["type", "value", "confidence"],
            },
        },
        "extracted_entities": {
            "type": "object",
            "properties": {
                "vendors": {"type": "array", "items": {"type": "string"}},
                "products": {"type": "array", "items": {"type": "string"}},
                "malware_families": {"type": "array", "items": {"type": "string"}},
                "threat_actors": {"type": "array", "items": {"type": "string"}},
            },
            "required": ["vendors", "products", "malware_families", "threat_actors"],
        },
        "attack_mappings": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "technique_id": {"type": "string"},
                    "technique_name": {"type": "string"},
                    "confidence": {"type": "number"},
                    "evidence": {"type": "string"},
                },
                "required": ["technique_id", "technique_name", "confidence", "evidence"],
            },
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
        },
        "confidence": {"type": "number"},
        "evidence": {
            "type": "array",
            "items": {"type": "string"},
        },
    },
    "required": [
        "summary",
        "extracted_cves",
        "extracted_iocs",
        "extracted_entities",
        "attack_mappings",
        "recommended_actions",
        "confidence",
        "evidence",
    ],
}

REPORT_SCHEMA = {
    "type": "object",
    "properties": {
        "title": {"type": "string"},
        "subtitle": {"type": "string"},
        "created_at": {"type": "string"},
        "source_entities": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "id": {"type": "string"},
                    "label": {"type": "string"},
                },
                "required": ["type", "id", "label"],
            },
        },
        "sections": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "heading": {"type": "string"},
                    "content": {"type": "string"},
                    "items": {"type": "array", "items": {"type": "string"}},
                    "links": {
                        "type": "array",
                        "items": {
                            "type": "object",
                            "properties": {
                                "label": {"type": "string"},
                                "url": {"type": "string"},
                            },
                            "required": ["label", "url"],
                        },
                    },
                    "columns": {"type": "array", "items": {"type": "string"}},
                    "rows": {
                        "type": "array",
                        "items": {"type": "array", "items": {"type": "string"}},
                    },
                },
                "required": ["type", "heading"],
            },
        },
    },
    "required": ["title", "subtitle", "created_at", "source_entities", "sections"],
}

EXTRACTED_IOCS_SCHEMA = {
    "type": "object",
    "properties": {
        "extracted_iocs": {
            "type": "array",
            "items": {
                "type": "object",
                "properties": {
                    "type": {"type": "string"},
                    "value": {"type": "string"},
                    "confidence": {"type": "number"},
                },
                "required": ["type", "value", "confidence"],
            },
        },
        "evidence": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    },
    "required": ["extracted_iocs", "evidence", "confidence"],
}

EXTRACTED_CVES_SCHEMA = {
    "type": "object",
    "properties": {
        "extracted_cves": {
            "type": "array",
            "items": {"type": "string"},
        },
        "evidence": {"type": "array", "items": {"type": "string"}},
        "confidence": {"type": "number"},
    },
    "required": ["extracted_cves", "evidence", "confidence"],
}


def is_vertex_ready():
    return genai is not None and os.getenv("USE_VERTEX_AI", "1") == "1"


def analyze_article(entity_id, selected_text):
    if not is_vertex_ready():
        raise RuntimeError("Vertex AI SDK is not available.")

    project = os.getenv("GOOGLE_CLOUD_PROJECT", "cybernews-496015")
    location = os.getenv("VERTEX_AI_LOCATION", "global")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    client = genai.Client(vertexai=True, project=project, location=location)
    prompt = build_article_prompt(entity_id, selected_text)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=ARTICLE_ANALYSIS_SCHEMA,
        ),
    )

    result = json.loads(response.text)
    return normalize_article_result(result), model


def generate_article_report(entity_id, selected_text, created_at):
    if not is_vertex_ready():
        raise RuntimeError("Vertex AI SDK is not available.")

    project = os.getenv("GOOGLE_CLOUD_PROJECT", "cybernews-496015")
    location = os.getenv("VERTEX_AI_LOCATION", "global")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    client = genai.Client(vertexai=True, project=project, location=location)
    prompt = build_report_prompt(entity_id, selected_text, created_at)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.2,
            response_mime_type="application/json",
            response_schema=REPORT_SCHEMA,
        ),
    )

    report = json.loads(response.text)
    return normalize_report(report, entity_id, created_at), model


def extract_article_iocs(entity_id, selected_text):
    result, model = run_simple_extraction(
        build_ioc_prompt(entity_id, selected_text),
        EXTRACTED_IOCS_SCHEMA,
    )
    return normalize_ioc_result(result), model


def extract_article_cves(entity_id, selected_text):
    result, model = run_simple_extraction(
        build_cve_prompt(entity_id, selected_text),
        EXTRACTED_CVES_SCHEMA,
    )
    return normalize_cve_result(result), model


def run_simple_extraction(prompt, schema):
    if not is_vertex_ready():
        raise RuntimeError("Vertex AI SDK is not available.")

    project = os.getenv("GOOGLE_CLOUD_PROJECT", "cybernews-496015")
    location = os.getenv("VERTEX_AI_LOCATION", "global")
    model = os.getenv("GEMINI_MODEL", "gemini-2.5-flash")

    client = genai.Client(vertexai=True, project=project, location=location)

    response = client.models.generate_content(
        model=model,
        contents=prompt,
        config=types.GenerateContentConfig(
            temperature=0.1,
            response_mime_type="application/json",
            response_schema=schema,
        ),
    )

    return json.loads(response.text), model


def build_article_prompt(entity_id, selected_text):
    return f"""
You are helping an analyst review a cybersecurity news item.

Rules:
- Return valid JSON only.
- Use only the article text below.
- Do not invent CVEs, IOCs, vendors, products, malware, actors, or ATT&CK techniques.
- If information is missing, return an empty list.
- Keep summaries short and clear.
- Evidence must quote or closely paraphrase article text.

Article ID:
{entity_id}

Article text:
{selected_text}
""".strip()


def build_report_prompt(entity_id, selected_text, created_at):
    return f"""
You are drafting a concise cyber threat intelligence report for an analyst.

Rules:
- Return valid JSON only.
- Use only the article text below.
- Do not invent facts, CVEs, IOCs, vendors, malware, actors, or patch information.
- Keep the report practical and readable.
- Use only these section types: summary, bullet_list, recommendations, source_links.
- Include an Executive Summary, Key Findings, and Recommended Actions.
- Include source_links only when the article text includes real source URLs.

Article ID:
{entity_id}

Created at:
{created_at}

Article text:
{selected_text}
""".strip()


def build_ioc_prompt(entity_id, selected_text):
    return f"""
Extract indicators of compromise from this cybersecurity article.

Rules:
- Return valid JSON only.
- Use only the article text below.
- Do not invent indicators.
- Supported IOC types: ipv4, ipv6, domain, url, sha256, sha1, md5, email, file_path, registry_key.
- If no IOCs are present, return an empty list.

Article ID:
{entity_id}

Article text:
{selected_text}
""".strip()


def build_cve_prompt(entity_id, selected_text):
    return f"""
Extract CVE identifiers from this cybersecurity article.

Rules:
- Return valid JSON only.
- Use only the article text below.
- Do not invent CVEs.
- Return CVE identifiers exactly in CVE-YYYY-NNNN format.
- If no CVEs are present, return an empty list.

Article ID:
{entity_id}

Article text:
{selected_text}
""".strip()


def normalize_article_result(result):
    summary = result.get("summary") or {}
    entities = result.get("extracted_entities") or {}

    return {
        "summary": {
            "executive": str(summary.get("executive", "")),
            "technical": str(summary.get("technical", "")),
            "key_points": list(summary.get("key_points", [])),
        },
        "extracted_cves": list(result.get("extracted_cves", [])),
        "extracted_iocs": list(result.get("extracted_iocs", [])),
        "extracted_entities": {
            "vendors": list(entities.get("vendors", [])),
            "products": list(entities.get("products", [])),
            "malware_families": list(entities.get("malware_families", [])),
            "threat_actors": list(entities.get("threat_actors", [])),
        },
        "attack_mappings": list(result.get("attack_mappings", [])),
        "recommended_actions": list(result.get("recommended_actions", [])),
        "confidence": float(result.get("confidence", 0.0)),
        "evidence": list(result.get("evidence", [])),
    }


def normalize_report(report, entity_id, created_at):
    sections = []

    for section in report.get("sections", []):
        section_type = section.get("type", "summary")

        if section_type not in {"summary", "bullet_list", "recommendations", "source_links"}:
            section_type = "summary"

        clean_section = {
            "type": section_type,
            "heading": str(section.get("heading", "Section")),
        }

        if section_type == "summary":
            clean_section["content"] = str(section.get("content", ""))
        elif section_type == "source_links":
            clean_section["links"] = normalize_links(section.get("links", []))
        else:
            clean_section["items"] = [str(item) for item in section.get("items", [])]

        sections.append(clean_section)

    if not sections:
        sections = [
            {
                "type": "summary",
                "heading": "Executive Summary",
                "content": "No report content was generated.",
            }
        ]

    return {
        "title": str(report.get("title", "Threat Intelligence Report")),
        "subtitle": str(report.get("subtitle", f"article: {entity_id}")),
        "created_at": str(report.get("created_at", created_at)),
        "source_entities": [
            {
                "type": "article",
                "id": entity_id,
                "label": entity_id,
            }
        ],
        "sections": sections,
    }


def normalize_ioc_result(result):
    iocs = []

    for ioc in result.get("extracted_iocs", []):
        iocs.append(
            {
                "type": str(ioc.get("type", "")),
                "value": str(ioc.get("value", "")),
                "confidence": float(ioc.get("confidence", 0.0)),
            }
        )

    return {
        "summary": {
            "executive": f"Found {len(iocs)} IOC(s).",
            "technical": "Indicators were extracted from the selected article text.",
            "key_points": [ioc["value"] for ioc in iocs],
        },
        "extracted_cves": [],
        "extracted_iocs": iocs,
        "extracted_entities": {
            "vendors": [],
            "products": [],
            "malware_families": [],
            "threat_actors": [],
        },
        "attack_mappings": [],
        "recommended_actions": ["Review extracted IOCs before taking action."],
        "confidence": float(result.get("confidence", 0.0)),
        "evidence": list(result.get("evidence", [])),
    }


def normalize_cve_result(result):
    cves = [str(cve) for cve in result.get("extracted_cves", [])]

    return {
        "summary": {
            "executive": f"Found {len(cves)} CVE reference(s).",
            "technical": "CVE identifiers were extracted from the selected article text.",
            "key_points": cves,
        },
        "extracted_cves": cves,
        "extracted_iocs": [],
        "extracted_entities": {
            "vendors": [],
            "products": [],
            "malware_families": [],
            "threat_actors": [],
        },
        "attack_mappings": [],
        "recommended_actions": ["Enrich extracted CVEs with NVD, CISA KEV, and EPSS before prioritizing."],
        "confidence": float(result.get("confidence", 0.0)),
        "evidence": list(result.get("evidence", [])),
    }


def normalize_links(links):
    clean_links = []

    for link in links:
        url = str(link.get("url", ""))

        if not url.startswith(("https://", "http://")):
            continue

        clean_links.append(
            {
                "label": str(link.get("label", url)),
                "url": url,
            }
        )

    return clean_links
