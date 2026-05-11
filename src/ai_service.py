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
