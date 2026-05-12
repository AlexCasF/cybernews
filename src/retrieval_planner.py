import re

from src.ai_service import plan_retrieval


ALLOWED_QUERY_TYPES = {
    "exact_cve",
    "exact_ioc",
    "vendor_product",
    "threat_actor",
    "malware_family",
    "phrase",
    "keyword",
}
ALLOWED_TARGETS = {"newsapi", "nvd", "cisa_kev", "epss"}
GENERIC_TERMS = {"cyber", "security", "news", "attack", "threat", "malware"}


def unique_strings(values):
    results = []

    for value in values or []:
        clean_value = str(value).strip()

        if clean_value and clean_value.lower() not in {item.lower() for item in results}:
            results.append(clean_value)

    return results


def extract_cves(text):
    return sorted({match.upper() for match in re.findall(r"CVE-\d{4}-\d{4,7}", text or "", re.IGNORECASE)})


def extract_keywords(text, limit=8):
    words = re.findall(r"[A-Za-z][A-Za-z0-9-]{4,}", (text or "").lower())
    keywords = []

    for word in words:
        if word in GENERIC_TERMS or word in keywords:
            continue

        keywords.append(word)

        if len(keywords) >= limit:
            break

    return keywords


def fallback_retrieval_plan(primary_article, selected_text):
    text = f"{primary_article.get('title', '')} {primary_article.get('summary', '')} {selected_text}"
    cves = extract_cves(text)
    keywords = extract_keywords(text)
    firestore_queries = []

    for cve in cves[:3]:
        firestore_queries.append({"type": "exact_cve", "terms": [cve], "priority": "high"})

    if keywords:
        firestore_queries.append({"type": "keyword", "terms": keywords[:5], "priority": "medium"})

    return {
        "topic": primary_article.get("title") or "Cybersecurity article",
        "confidence": 0.55,
        "core_entities": {
            "cves": cves,
            "iocs": [],
            "vendors": [],
            "products": [],
            "threat_actors": [],
            "malware_families": [],
            "vulnerability_names": [],
            "attack_terms": keywords[:4],
        },
        "priority_search_terms": keywords,
        "exact_terms": cves,
        "negative_terms": [],
        "firestore_queries": firestore_queries[:5],
        "source_api_queries": [
            {
                "target": "nvd",
                "query": "",
                "cve_ids": cves[:3],
                "from_days_ago": 180,
                "max_results": 10,
                "priority": "high",
            }
        ] if cves else [],
        "web_queries": [],
    }


def clean_query(query):
    clean_terms = unique_strings(query.get("terms", []))
    clean_terms = [term.upper() if re.fullmatch(r"cve-\d{4}-\d{4,7}", term, re.IGNORECASE) else term for term in clean_terms]

    if not clean_terms:
        return None

    query_type = query.get("type", "keyword")

    if query_type not in ALLOWED_QUERY_TYPES:
        query_type = "keyword"

    return {
        "type": query_type,
        "terms": clean_terms[:8],
        "priority": query.get("priority") if query.get("priority") in {"high", "medium", "low"} else "medium",
    }


def clean_source_query(query):
    target = query.get("target")

    if target not in ALLOWED_TARGETS:
        return None

    cve_ids = [cve.upper() for cve in unique_strings(query.get("cve_ids", [])) if re.fullmatch(r"CVE-\d{4}-\d{4,7}", cve, re.IGNORECASE)]
    clean_query_text = str(query.get("query", "")).strip()

    if not cve_ids and len(clean_query_text) < 4:
        return None

    return {
        "target": target,
        "query": clean_query_text,
        "cve_ids": cve_ids[:5],
        "from_days_ago": int(query.get("from_days_ago", 180) or 180),
        "max_results": min(int(query.get("max_results", 10) or 10), 10),
        "priority": query.get("priority") if query.get("priority") in {"high", "medium", "low"} else "medium",
    }


def clean_web_query(query):
    clean_query_text = str(query.get("query", "")).strip()

    if len(clean_query_text) < 5:
        return None

    return {
        "query": clean_query_text,
        "purpose": str(query.get("purpose", "supporting context")),
        "priority": query.get("priority") if query.get("priority") in {"high", "medium", "low"} else "medium",
    }


def validate_retrieval_plan(plan):
    fallback = fallback_retrieval_plan({}, "")
    clean_plan = {
        "topic": str(plan.get("topic") or fallback["topic"]),
        "confidence": float(plan.get("confidence", 0.5) or 0.5),
        "core_entities": {},
        "priority_search_terms": unique_strings(plan.get("priority_search_terms", []))[:10],
        "exact_terms": unique_strings(plan.get("exact_terms", []))[:10],
        "negative_terms": unique_strings(plan.get("negative_terms", []))[:10],
        "firestore_queries": [],
        "source_api_queries": [],
        "web_queries": [],
    }
    entities = plan.get("core_entities") or {}

    for key in ["cves", "iocs", "vendors", "products", "threat_actors", "malware_families", "vulnerability_names", "attack_terms"]:
        values = unique_strings(entities.get(key, []))

        if key == "cves":
            values = [value.upper() for value in values if re.fullmatch(r"CVE-\d{4}-\d{4,7}", value, re.IGNORECASE)]

        clean_plan["core_entities"][key] = values[:10]

    for query in plan.get("firestore_queries", [])[:8]:
        clean_query_value = clean_query(query)

        if clean_query_value:
            clean_plan["firestore_queries"].append(clean_query_value)

        if len(clean_plan["firestore_queries"]) >= 5:
            break

    for query in plan.get("source_api_queries", [])[:5]:
        clean_query_value = clean_source_query(query)

        if clean_query_value:
            clean_plan["source_api_queries"].append(clean_query_value)

        if len(clean_plan["source_api_queries"]) >= 3:
            break

    for query in plan.get("web_queries", [])[:5]:
        clean_query_value = clean_web_query(query)

        if clean_query_value:
            clean_plan["web_queries"].append(clean_query_value)

        if len(clean_plan["web_queries"]) >= 3:
            break

    return clean_plan


def plan_retrieval_with_gemini(action, primary_article, selected_text, context_depth):
    try:
        plan, model = plan_retrieval(action, primary_article, selected_text, context_depth)
        return validate_retrieval_plan(plan), model, ""
    except Exception as error:
        return validate_retrieval_plan(fallback_retrieval_plan(primary_article, selected_text)), "fallback-planner-v1", str(error)
