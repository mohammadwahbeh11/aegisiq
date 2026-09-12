"""
app/enrichment -- threat intelligence enrichment layer.

Every alert with a source IP can be automatically enriched with:
  * AbuseIPDB reputation score (0-100 abuse confidence)
  * AlienVault OTX pulses (which threat campaigns has this IP appeared in?)
  * Cached lookups (6 hour TTL) to stay under free-tier API limits

Free tiers used:
  * AbuseIPDB: 1000 lookups/day (register at abuseipdb.com/register)
  * AlienVault OTX: 10000 lookups/hour, no key needed for basic queries

This turns "203.0.113.42 hit us 5 times" into "203.0.113.42 is a
known TOR exit node, 87% abuse confidence, tagged in the 'Hydra
Brute Force' pulse from 2024" — the difference between an alert an
analyst dismisses and one they act on immediately.
"""
from app.enrichment.enrichment_service import EnrichmentService  # noqa: F401
