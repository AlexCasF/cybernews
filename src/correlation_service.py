from datetime import datetime

from src.storage import list_feed_items, save_article_correlations


SCORE_WEIGHTS = {
    "same_cve": 12,
    "same_ioc": 11,
    "same_threat_actor": 9,
    "same_malware_family": 8,
    "same_vendor_product_pair": 8,
    "same_vulnerability_name": 7,
    "same_attack_term": 6,
    "same_vendor": 4,
    "same_product": 4,
    "keyphrase_match": 3,
    "keyword_match": 1,
    "same_source_type": 0.5,
}


def get_limit(context_depth):
    if context_depth == "low":
        return 3

    if context_depth == "high":
        return 15

    return 6


def terms_from_plan(retrieval_plan):
    entities = retrieval_plan.get("core_entities", {})
    return {
        "cves": [value.lower() for value in entities.get("cves", [])],
        "iocs": [value.lower() for value in entities.get("iocs", [])],
        "vendors": [value.lower() for value in entities.get("vendors", [])],
        "products": [value.lower() for value in entities.get("products", [])],
        "threat_actors": [value.lower() for value in entities.get("threat_actors", [])],
        "malware_families": [value.lower() for value in entities.get("malware_families", [])],
        "vulnerability_names": [value.lower() for value in entities.get("vulnerability_names", [])],
        "attack_terms": [value.lower() for value in entities.get("attack_terms", [])],
        "priority": [value.lower() for value in retrieval_plan.get("priority_search_terms", [])],
        "exact": [value.lower() for value in retrieval_plan.get("exact_terms", [])],
    }


def add_match(matches, relation_types, term, relation_type):
    if term and term not in matches:
        matches.append(term)

    if relation_type not in relation_types:
        relation_types.append(relation_type)


def score_article_relation(primary_article, retrieval_plan, candidate):
    haystack = " ".join(
        [
            str(candidate.get("title", "")),
            str(candidate.get("summary", "")),
            " ".join(candidate.get("search_terms", [])),
            " ".join(candidate.get("keyphrases", [])),
            " ".join(candidate.get("cve_ids", [])),
            " ".join(candidate.get("ioc_values", [])),
        ]
    ).lower()
    terms = terms_from_plan(retrieval_plan)
    matched_terms = []
    relation_types = []
    score = 0.0

    for cve in terms["cves"] + terms["exact"]:
        if cve.startswith("cve-") and cve in haystack:
            score += SCORE_WEIGHTS["same_cve"]
            add_match(matched_terms, relation_types, cve.upper(), "same_cve")

    for ioc in terms["iocs"]:
        if ioc in haystack:
            score += SCORE_WEIGHTS["same_ioc"]
            add_match(matched_terms, relation_types, ioc, "same_ioc")

    for value, relation_type in [
        ("threat_actors", "same_threat_actor"),
        ("malware_families", "same_malware_family"),
        ("vulnerability_names", "same_vulnerability_name"),
        ("attack_terms", "same_attack_term"),
        ("vendors", "same_vendor"),
        ("products", "same_product"),
    ]:
        for term in terms[value]:
            if term in haystack:
                score += SCORE_WEIGHTS[relation_type]
                add_match(matched_terms, relation_types, term, relation_type)

    for phrase in candidate.get("keyphrases", []):
        if phrase in terms["priority"]:
            score += SCORE_WEIGHTS["keyphrase_match"]
            add_match(matched_terms, relation_types, phrase, "keyphrase_match")

    for term in terms["priority"]:
        if term in haystack:
            score += SCORE_WEIGHTS["keyword_match"]
            add_match(matched_terms, relation_types, term, "keyword_match")

    if candidate.get("source_type") == primary_article.get("source_type"):
        score += SCORE_WEIGHTS["same_source_type"]

    if relation_types == ["keyword_match"] or relation_types == ["same_source_type"]:
        score = min(score, 4.0)

    return {
        "score": score,
        "matched_terms": matched_terms,
        "relation_types": relation_types,
        "confidence": min(score / 15, 1.0),
    }


def normalize_related_article(candidate, relation, index):
    relation_label = ", ".join(relation["relation_types"]) if relation["relation_types"] else "keyword relation"

    return {
        "source_ref": f"DB{index}",
        "origin": "firestore",
        "article_id": candidate.get("id", ""),
        "title": candidate.get("title", "Untitled article"),
        "summary": candidate.get("summary", ""),
        "source": candidate.get("source", "Unknown source"),
        "source_type": candidate.get("source_type", "unknown"),
        "url": candidate.get("url", "#"),
        "published": candidate.get("published", "Unknown date"),
        "matched_terms": relation["matched_terms"],
        "relation_types": relation["relation_types"],
        "score": round(relation["score"], 2),
        "confidence": round(relation["confidence"], 2),
        "why_related": f"Matched by {relation_label}.",
    }


def rank_related_articles(primary_article, retrieval_plan, candidates, limit):
    scored = []
    seen_urls = {primary_article.get("url")}

    for candidate in candidates:
        if candidate.get("id") == primary_article.get("id"):
            continue

        if candidate.get("url") in seen_urls:
            continue

        relation = score_article_relation(primary_article, retrieval_plan, candidate)

        if relation["score"] <= 0:
            continue

        scored.append((candidate, relation))
        seen_urls.add(candidate.get("url"))

    scored.sort(key=lambda item: (item[1]["score"], item[0].get("published_sort", "")), reverse=True)
    return [
        normalize_related_article(candidate, relation, index + 1)
        for index, (candidate, relation) in enumerate(scored[:limit])
    ]


def search_firestore_from_plan(primary_article, retrieval_plan, context_depth):
    candidates = list_feed_items()
    limit = get_limit(context_depth)
    related_articles = rank_related_articles(primary_article, retrieval_plan, candidates, limit)
    correlations = [
        {
            "primary_article_id": primary_article.get("id", ""),
            "related_article_id": article["article_id"],
            "score": article["score"],
            "confidence": article["confidence"],
            "relation_types": article["relation_types"],
            "matched_terms": article["matched_terms"],
            "evidence": [article["why_related"]],
            "related_title": article["title"],
            "related_source": article["source"],
            "related_url": article["url"],
            "related_published": article["published"],
            "created_at": datetime.utcnow().isoformat(),
            "correlation_version": "correlation-v1",
        }
        for article in related_articles
    ]

    if correlations:
        save_article_correlations(primary_article.get("id", ""), correlations)

    return related_articles


def dedupe_sources(sources):
    seen = set()
    deduped = []

    for source in sources:
        key = source.get("url") or source.get("article_id") or source.get("title")

        if key in seen:
            continue

        seen.add(key)
        deduped.append(source)

    return deduped
