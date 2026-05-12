def get_context_limit(context_depth):
    if context_depth == "low":
        return 3

    if context_depth == "high":
        return 15

    return 6


def build_primary_article(primary_article, selected_text):
    return {
        "source_ref": "A0",
        "article_id": primary_article.get("id", ""),
        "title": primary_article.get("title", "Selected article"),
        "summary": primary_article.get("summary", ""),
        "source": primary_article.get("source", "Unknown source"),
        "source_type": primary_article.get("source_type", "unknown"),
        "url": primary_article.get("url", "#"),
        "published": primary_article.get("published", "Unknown date"),
        "category": primary_article.get("category", "News"),
        "severity": primary_article.get("severity", "Low"),
        "selected_text": selected_text,
    }


def build_source_map(primary_article, internal_sources, external_sources, cve_enrichments):
    source_map = {
        "A0": {
            "title": primary_article.get("title", "Selected article"),
            "url": primary_article.get("url", "#"),
            "origin": "primary",
        }
    }

    for source in internal_sources + external_sources:
        source_ref = source.get("source_ref")

        if source_ref:
            source_map[source_ref] = {
                "title": source.get("title", ""),
                "url": source.get("url", "#"),
                "origin": source.get("origin", "unknown"),
            }

    for enrichment in cve_enrichments:
        source_ref = enrichment.get("source_ref")

        if source_ref:
            source_map[source_ref] = {
                "title": enrichment.get("cve_id", ""),
                "url": "",
                "origin": enrichment.get("origin", "nvd_cisa_epss"),
            }

    return source_map


def build_context_bundle(
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
):
    limit = get_context_limit(context_depth)
    combined_sources = (firestore_results + external_results)[:limit]
    internal_sources = [source for source in combined_sources if source.get("origin") == "firestore"]
    external_sources = [source for source in combined_sources if source.get("origin") != "firestore"]
    primary = build_primary_article(primary_article, selected_text)

    return {
        "action": action,
        "context_depth": context_depth,
        "primary_article": primary,
        "retrieval_plan": retrieval_plan,
        "internal_sources": internal_sources,
        "external_sources": external_sources,
        "cve_enrichments": cve_enrichments,
        "ioc_sightings": ioc_sightings,
        "source_map": build_source_map(primary, internal_sources, external_sources, cve_enrichments),
        "retrieval_trace": retrieval_trace,
    }
