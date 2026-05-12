import json
import os
from datetime import datetime, timedelta
from urllib.parse import urlencode
from urllib.request import Request, urlopen

from src.storage import save_external_context_cache


NEWSAPI_URL = "https://newsapi.org/v2/everything"
NVD_CVE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
EPSS_URL = "https://api.first.org/data/v1/epss"


def get_json(url, headers=None, timeout=8):
    request = Request(url, headers=headers or {"User-Agent": "CyberNewsSchoolProject/1.0"})

    with urlopen(request, timeout=timeout) as response:
        return json.loads(response.read().decode("utf-8"))


def search_newsapi_historical(query, from_days_ago=180, max_results=10):
    api_key = os.getenv("NEWS_API_KEY")

    if not api_key or not query:
        return []

    from_date = (datetime.utcnow() - timedelta(days=from_days_ago)).strftime("%Y-%m-%d")
    params = urlencode(
        {
            "q": query,
            "language": "en",
            "sortBy": "publishedAt",
            "from": from_date,
            "pageSize": max_results,
            "apiKey": api_key,
        }
    )

    try:
        data = get_json(f"{NEWSAPI_URL}?{params}")
    except Exception:
        return []

    if data.get("status") != "ok":
        return []

    results = []

    for index, article in enumerate(data.get("articles", [])[:max_results], start=1):
        title = article.get("title")
        url = article.get("url")

        if not title or not url:
            continue

        results.append(
            {
                "source_ref": f"NEWS{index}",
                "origin": "newsapi",
                "title": title,
                "summary": article.get("description") or "",
                "snippet": article.get("description") or "",
                "source": article.get("source", {}).get("name") or "NewsAPI",
                "url": url,
                "published": (article.get("publishedAt") or "")[:10] or "Unknown date",
                "query": query,
                "matched_terms": [query],
                "relation_types": ["external_query_match"],
                "score": 3.0,
            }
        )

    save_external_context_cache(results)
    return results


def search_nvd_for_cves(cve_ids):
    results = {}
    api_key = os.getenv("NVD_API_KEY")

    for cve_id in cve_ids:
        params = urlencode({"cveId": cve_id})
        headers = {"User-Agent": "CyberNewsSchoolProject/1.0"}

        if api_key:
            headers["apiKey"] = api_key

        try:
            data = get_json(f"{NVD_CVE_URL}?{params}", headers=headers, timeout=10)
        except Exception:
            continue

        vulnerabilities = data.get("vulnerabilities", [])

        if not vulnerabilities:
            continue

        cve = vulnerabilities[0].get("cve", {})
        descriptions = cve.get("descriptions", [])
        summary = ""

        for description in descriptions:
            if description.get("lang") == "en":
                summary = description.get("value", "")
                break

        results[cve_id] = {
            "id": cve.get("id", cve_id),
            "summary": summary,
            "references": [ref.get("url", "") for ref in cve.get("references", {}).get("referenceData", [])],
            "metrics": cve.get("metrics", {}),
        }

    return results


def search_cisa_kev_for_cves(cve_ids):
    try:
        data = get_json(CISA_KEV_URL, timeout=10)
    except Exception:
        return {}

    wanted = {cve_id.upper() for cve_id in cve_ids}
    results = {}

    for item in data.get("vulnerabilities", []):
        cve_id = item.get("cveID", "").upper()

        if cve_id in wanted:
            results[cve_id] = {
                "is_known_exploited": True,
                "vendor": item.get("vendorProject", ""),
                "product": item.get("product", ""),
                "due_date": item.get("dueDate", ""),
                "known_ransomware_use": item.get("knownRansomwareCampaignUse", ""),
                "required_action": item.get("requiredAction", ""),
            }

    return results


def search_epss_for_cves(cve_ids):
    if not cve_ids:
        return {}

    params = urlencode({"cve": ",".join(cve_ids)})

    try:
        data = get_json(f"{EPSS_URL}?{params}", timeout=10)
    except Exception:
        return {}

    return {
        item.get("cve", "").upper(): {
            "epss": item.get("epss"),
            "percentile": item.get("percentile"),
            "date": item.get("date"),
        }
        for item in data.get("data", [])
    }


def build_cve_enrichments(cve_ids):
    clean_cves = []

    for cve_id in cve_ids:
        clean_cve = str(cve_id).upper()

        if clean_cve.startswith("CVE-") and clean_cve not in clean_cves:
            clean_cves.append(clean_cve)

    nvd = search_nvd_for_cves(clean_cves)
    kev = search_cisa_kev_for_cves(clean_cves)
    epss = search_epss_for_cves(clean_cves)
    enrichments = []

    for index, cve_id in enumerate(clean_cves, start=1):
        enrichment = {
            "source_ref": f"CVE{index}",
            "origin": "nvd_cisa_epss",
            "cve_id": cve_id,
            "nvd": nvd.get(cve_id, {}),
            "kev": kev.get(cve_id, {"is_known_exploited": False}),
            "epss": epss.get(cve_id, {}),
            "risk_summary": "Review deterministic NVD, CISA KEV, and EPSS data.",
            "source_links": [],
        }

        if enrichment["nvd"].get("references"):
            enrichment["source_links"].extend(enrichment["nvd"]["references"][:3])

        enrichments.append(enrichment)

    save_external_context_cache(enrichments)
    return enrichments


def should_use_external_search(action, retrieval_plan, firestore_results, external_search_policy):
    if external_search_policy == "off":
        return False

    if external_search_policy == "force" and action in {"analyze", "generate_report"}:
        return True

    if action == "extract_iocs":
        return False

    if action == "generate_report":
        return True

    strong_matches = [item for item in firestore_results if item.get("score", 0) >= 6]
    has_entities = any(retrieval_plan.get("core_entities", {}).get(key) for key in ["cves", "vendors", "products", "threat_actors", "malware_families"])

    return len(strong_matches) < 3 or (action == "analyze" and has_entities)


def search_web_from_plan(retrieval_plan, max_queries=3, max_results_per_query=5):
    return []


def search_external_sources_from_plan(retrieval_plan, context_depth):
    results = []

    for query in retrieval_plan.get("source_api_queries", []):
        if query.get("target") == "newsapi":
            results.extend(
                search_newsapi_historical(
                    query.get("query", ""),
                    int(query.get("from_days_ago", 180)),
                    int(query.get("max_results", 10)),
                )
            )

    return results
