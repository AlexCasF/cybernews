import re

from src.ai_service import write_agentic_artifact
from src.context_builder import build_context_bundle
from src.correlation_service import dedupe_sources, search_firestore_from_plan
from src.external_retrieval import (
    build_cve_enrichments,
    search_external_sources_from_plan,
    should_use_external_search,
)
from src.retrieval_planner import fallback_retrieval_plan, plan_retrieval_with_gemini
from src.storage import get_feed_item


def parse_selected_text(selected_text, entity_id):
    lines = [line.strip() for line in (selected_text or "").splitlines() if line.strip()]
    title = lines[0] if lines else entity_id
    source = "Unknown source"
    url = "#"
    summary_lines = []

    for line in lines[1:]:
        if line.lower().startswith("source:"):
            source = line.split(":", 1)[1].strip() or source
        elif line.lower().startswith("url:"):
            url = line.split(":", 1)[1].strip() or url
        else:
            summary_lines.append(line)

    return {
        "id": entity_id,
        "title": title,
        "summary": " ".join(summary_lines),
        "source": source,
        "source_type": "selected",
        "url": url,
        "published": "Unknown date",
        "category": "News",
        "severity": "Low",
    }


def load_primary_article(entity_id, selected_text):
    article = get_feed_item(entity_id)

    if article:
        return article, "Loaded primary article from Firestore."

    return parse_selected_text(selected_text, entity_id), "Primary article was not in Firestore; used selected text fallback."


def extract_iocs_from_text(text):
    patterns = [
        ("ipv4", r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
        ("url", r"https?://[^\s]+"),
        ("email", r"\b[\w.+-]+@[\w.-]+\.[a-zA-Z]{2,}\b"),
        ("hash", r"\b[a-fA-F0-9]{32,64}\b"),
    ]
    iocs = []

    for ioc_type, pattern in patterns:
        for match in re.findall(pattern, text or ""):
            clean_match = match.rstrip(".,;")
            iocs.append(
                {
                    "type": ioc_type,
                    "value": clean_match,
                    "confidence": 0.8,
                    "evidence": clean_match,
                    "source_refs": ["A0"],
                }
            )

    return iocs


def extract_cves_from_text(text):
    return sorted({match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text or "", re.IGNORECASE)})


def build_ioc_sightings(iocs, sources):
    sightings = []

    for ioc in iocs:
        value = ioc.get("value", "")
        seen_in = []

        for source in sources:
            haystack = f"{source.get('title', '')} {source.get('summary', '')}".lower()

            if value and value.lower() in haystack:
                seen_in.append(
                    {
                        "source_ref": source.get("source_ref", ""),
                        "title": source.get("title", ""),
                        "url": source.get("url", "#"),
                        "source": source.get("source", ""),
                        "published": source.get("published", ""),
                    }
                )

        if seen_in:
            sightings.append(
                {
                    "ioc": value,
                    "type": ioc.get("type", "unknown"),
                    "seen_in": seen_in,
                    "sighting_count": len(seen_in),
                }
            )

    return sightings


def build_fallback_artifact(action, context_bundle):
    primary = context_bundle["primary_article"]
    text = f"{primary.get('title', '')} {primary.get('summary', '')} {primary.get('selected_text', '')}"
    cves = extract_cves_from_text(text)
    iocs = extract_iocs_from_text(text)
    related_sources = context_bundle["internal_sources"] + context_bundle["external_sources"]

    artifact = {
        "artifact_type": action,
        "summary": {
            "executive": f"Reviewed {primary.get('title', 'the selected article')}.",
            "technical": "Fallback artifact generated from deterministic retrieval context.",
            "key_points": [source.get("title", "") for source in related_sources[:3]],
        },
        "primary_findings": [
            {
                "finding": primary.get("summary") or primary.get("title", "Primary article reviewed."),
                "source_refs": ["A0"],
                "confidence": 0.7,
            }
        ],
        "correlated_findings": [
            {
                "finding": source.get("why_related", "Related source found."),
                "relation_type": ", ".join(source.get("relation_types", [])) or "related",
                "matched_terms": source.get("matched_terms", []),
                "source_refs": ["A0", source.get("source_ref", "")],
                "confidence": source.get("confidence", 0.5),
            }
            for source in related_sources
        ],
        "extracted_cves": cves,
        "extracted_iocs": iocs,
        "entities": {},
        "attack_mappings": [],
        "recommended_actions": ["Review related sources and deterministic CVE enrichment before taking action."],
        "related_sources": related_sources,
        "source_map": context_bundle["source_map"],
        "confidence": 0.65,
        "evidence": ["Generated with deterministic fallback writer."],
    }

    if action == "extract_cves":
        artifact["summary"]["executive"] = f"Found {len(cves)} CVE reference(s) in the primary article context."

    if action == "extract_iocs":
        artifact["summary"]["executive"] = f"Found {len(iocs)} IOC(s) in the primary article context."

    return artifact


def artifact_to_result_json(artifact, context_bundle):
    result_json = {
        "artifact_type": artifact.get("artifact_type", "analysis"),
        "summary": artifact.get("summary", {}),
        "primary_findings": artifact.get("primary_findings", []),
        "correlated_findings": artifact.get("correlated_findings", []),
        "extracted_cves": artifact.get("extracted_cves", []),
        "extracted_iocs": artifact.get("extracted_iocs", []),
        "extracted_entities": artifact.get("entities", {}),
        "attack_mappings": artifact.get("attack_mappings", []),
        "recommended_actions": artifact.get("recommended_actions", []),
        "related_articles": context_bundle.get("internal_sources", []),
        "related_sources": artifact.get("related_sources", context_bundle.get("internal_sources", []) + context_bundle.get("external_sources", [])),
        "source_map": artifact.get("source_map", context_bundle.get("source_map", {})),
        "cve_enrichments": context_bundle.get("cve_enrichments", []),
        "ioc_sightings": context_bundle.get("ioc_sightings", []),
        "confidence": artifact.get("confidence", 0.6),
        "evidence": artifact.get("evidence", []),
    }

    if "vendors" not in result_json["extracted_entities"]:
        result_json["extracted_entities"] = {
            "vendors": [],
            "products": [],
            "malware_families": [],
            "threat_actors": [],
            **result_json["extracted_entities"],
        }

    return result_json


def build_report_json(artifact, context_bundle, created_at):
    primary = context_bundle["primary_article"]
    related_sources = artifact.get("related_sources", context_bundle.get("internal_sources", []) + context_bundle.get("external_sources", []))
    cve_enrichments = context_bundle.get("cve_enrichments", [])

    return {
        "title": artifact.get("title") or f"Threat Intelligence Report: {primary.get('title', 'Selected Article')}",
        "subtitle": f"Primary source: {primary.get('source', 'Unknown source')}",
        "created_at": created_at,
        "source_entities": [
            {
                "type": "article",
                "id": primary.get("article_id", ""),
                "label": primary.get("title", ""),
            }
        ],
        "sections": [
            {
                "type": "summary",
                "heading": "Executive Summary",
                "content": artifact.get("summary", {}).get("executive", "No summary available."),
            },
            {
                "type": "bullet_list",
                "heading": "Key Findings",
                "items": artifact.get("summary", {}).get("key_points", []),
            },
            {
                "type": "table",
                "heading": "Related Articles",
                "columns": ["Relation", "Source", "Published", "Matched Terms"],
                "rows": [
                    [
                        ", ".join(source.get("relation_types", [])) or source.get("origin", ""),
                        source.get("source", ""),
                        source.get("published", ""),
                        ", ".join(source.get("matched_terms", [])),
                    ]
                    for source in related_sources
                ],
            },
            {
                "type": "table",
                "heading": "CVE Enrichment",
                "columns": ["CVE", "EPSS", "KEV", "Affected Product"],
                "rows": [
                    [
                        enrichment.get("cve_id", ""),
                        str(enrichment.get("epss", {}).get("epss", "unknown")),
                        "yes" if enrichment.get("kev", {}).get("is_known_exploited") else "no",
                        f"{enrichment.get('kev', {}).get('vendor', '')} {enrichment.get('kev', {}).get('product', '')}".strip(),
                    ]
                    for enrichment in cve_enrichments
                ],
            },
            {
                "type": "recommendations",
                "heading": "Recommended Actions",
                "items": artifact.get("recommended_actions", []),
            },
            {
                "type": "source_links",
                "heading": "Sources",
                "links": [
                    {
                        "label": f"{source.get('source_ref', '')}: {source.get('title', '')}",
                        "url": source.get("url", "#"),
                    }
                    for source in [{"source_ref": "A0", **primary}] + related_sources
                    if source.get("url", "#") != "#"
                ],
            },
        ],
    }


def run_agentic_article_action(
    action,
    entity_id,
    selected_text,
    context_depth="medium",
    output_format="structured_json",
    external_search_policy="auto",
    created_at="",
):
    retrieval_trace = []
    primary_article, load_message = load_primary_article(entity_id, selected_text)
    retrieval_trace.append({"step": "primary_article", "details": load_message, "count": 1})

    retrieval_plan, planner_model, planner_error = plan_retrieval_with_gemini(action, primary_article, selected_text, context_depth)
    retrieval_trace.append(
        {
            "step": "retrieval_plan",
            "details": "Gemini retrieval plan generated." if not planner_error else f"Fallback retrieval plan used: {planner_error}",
            "count": len(retrieval_plan.get("firestore_queries", [])),
        }
    )

    firestore_results = search_firestore_from_plan(primary_article, retrieval_plan, context_depth)
    retrieval_trace.append({"step": "firestore_search", "details": "Searched stored feed items.", "count": len(firestore_results)})

    external_results = []

    if should_use_external_search(action, retrieval_plan, firestore_results, external_search_policy):
        external_results = search_external_sources_from_plan(retrieval_plan, context_depth)
        retrieval_trace.append({"step": "external_search", "details": "Searched configured external source APIs.", "count": len(external_results)})
    else:
        retrieval_trace.append({"step": "external_search", "details": "External article search skipped by policy.", "count": 0})

    all_sources = dedupe_sources(firestore_results + external_results)
    primary_text = f"{primary_article.get('title', '')} {primary_article.get('summary', '')} {selected_text}"
    plan_cves = retrieval_plan.get("core_entities", {}).get("cves", [])
    cves = sorted(set(plan_cves + extract_cves_from_text(primary_text)))
    cve_enrichments = build_cve_enrichments(cves)
    iocs = extract_iocs_from_text(primary_text)
    ioc_sightings = build_ioc_sightings(iocs, all_sources)
    retrieval_trace.append({"step": "cve_ioc_enrichment", "details": "Loaded deterministic CVE enrichment and IOC sightings.", "count": len(cve_enrichments) + len(ioc_sightings)})

    context_bundle = build_context_bundle(
        action,
        primary_article,
        retrieval_plan,
        firestore_results,
        external_results,
        cve_enrichments,
        ioc_sightings,
        context_depth,
        selected_text,
        retrieval_trace,
    )
    retrieval_trace.append({"step": "context_bundle", "details": "Built source-linked context bundle.", "count": len(context_bundle["source_map"])})

    try:
        artifact, writer_model = write_agentic_artifact(action, context_bundle)
        model = writer_model
        warnings = []
    except Exception as error:
        artifact = build_fallback_artifact(action, context_bundle)
        model = "fallback-writer-v1"
        warnings = [f"Gemini artifact writer unavailable, used deterministic fallback: {error}"]

    result_json = artifact_to_result_json(artifact, context_bundle)
    report_json = None

    if action == "generate_report" or output_format in {"html_report", "both"}:
        report_json = build_report_json(artifact, context_bundle, created_at)

    return {
        "model": model,
        "planner_model": planner_model,
        "result_json": result_json,
        "report_json": report_json,
        "context_bundle": context_bundle,
        "retrieval_plan": retrieval_plan,
        "retrieval_trace": retrieval_trace,
        "related_sources": context_bundle.get("internal_sources", []) + context_bundle.get("external_sources", []),
        "source_map": context_bundle.get("source_map", {}),
        "warnings": warnings,
    }
