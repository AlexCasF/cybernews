# CyberNews Data Sources

Checked: 2026-05-11

This file tracks useful free or low-cost data sources for CyberNews.

## Current Sources

| Source | Access | Cost | Current status | Notes |
| --- | --- | --- | --- | --- |
| NewsAPI | REST API with `NEWS_API_KEY` | Free developer plan, limited and not for production | Integrated | Good for general cybersecurity headlines. Keep fallback behavior because the free tier is limited. |
| BSI WID advisories | Public RSS/XML | Free, no key | Integrated | Strong source for vulnerability advisories. German text, but useful severity data. |

## Best Next Sources

| Source | Access | Cost | Fit | Plan |
| --- | --- | --- | --- | --- |
| CISA KEV Catalog | Public JSON | Free, no key | Known exploited CVEs | Add `/api/kev-vulnerabilities`, then show a vulnerability panel on the dashboard. |
| FIRST EPSS | Public REST API | Free, no key | Exploit probability scoring | Add after KEV, using CVE IDs from the KEV feed. |
| NVD CVE API | Public REST API | Free, API key recommended for better limits | CVE details and CVSS data | Use later for deeper CVE details after KEV and EPSS are working. |

## Good News And RSS Sources

| Source | Access | Cost | Fit | Plan |
| --- | --- | --- | --- | --- |
| The Hacker News | Public feed | No key needed | Cybersecurity news | Add as a normalized RSS source after vulnerability data. |
| SecurityWeek | Public RSS feed | No key needed | Cybersecurity news | Add as a normalized RSS source after The Hacker News or beside it. |
| BleepingComputer | Public RSS feed | No key needed | Cybersecurity and malware news | Useful extra source if the dashboard needs more volume. |
| Hacker News API/RSS | Public API/RSS | Free, no key | Community signal | Use later as a "developer discussion" signal, not primary threat intelligence. |
| NewsData.io | REST API with key | Has a free tier, but limited | NewsAPI fallback | Keep as a backup option if NewsAPI limits become a problem. |

## Possible IOC Sources

| Source | Access | Cost | Fit | Plan |
| --- | --- | --- | --- | --- |
| URLhaus by abuse.ch | Public datasets/API | Free community/fair-use data | Malicious URLs | Good later source for IOC tracking. Review terms before automating. |
| MalwareBazaar by abuse.ch | Public community API | Free under fair-use principles | Malware hashes and samples | Useful later for hash-based IOC enrichment. Avoid downloading malware samples in this school app. |
| OpenPhish Community Feed | Public community feed | Free community feed | Phishing URLs | Possible later IOC source. Review terms before use. |
| GitHub Advisory Database | Web/API data | Free data, API access may need GitHub auth | Open-source package advisories | Useful later for software supply chain vulnerabilities. |

## Implementation Order

1. Add CISA KEV JSON API route.
2. Show recent known exploited vulnerabilities in the dashboard.
3. Add FIRST EPSS scoring for CVEs.
4. Add EPSS labels and simple filtering.
5. Connect CVE nodes into the threat graph.
6. Add more normalized RSS news sources.
7. Add a small IOC feed only after CVE and news data are stable.
8. Add AI enrichment after the data model is clear.

## Source Links

- CISA KEV Catalog: https://www.cisa.gov/known-exploited-vulnerabilities-catalog
- CISA KEV JSON: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
- FIRST EPSS API: https://api.first.org/epss/
- NVD Vulnerability API: https://nvd.nist.gov/developers/vulnerabilities
- NewsAPI docs: https://newsapi.org/docs
- NewsAPI pricing: https://newsapi.org/pricing
- The Hacker News feed: https://thehackernews.com/feeds/posts/default
- SecurityWeek feed: https://www.securityweek.com/feed/
- BleepingComputer feed: https://www.bleepingcomputer.com/feed/
- Hacker News API: https://github.com/HackerNews/API
- URLhaus feeds: https://urlhaus.abuse.ch/feeds/
- MalwareBazaar API: https://bazaar.abuse.ch/api/
- OpenPhish feeds: https://openphish.com/phishing_feeds.html
