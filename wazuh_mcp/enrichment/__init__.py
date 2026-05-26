"""Alert enrichment pipeline — pluggable enrichers for raw Wazuh alerts."""
from .pipeline import EnrichmentPipeline, enrich_alert, enrich_alerts_batch

__all__ = ["EnrichmentPipeline", "enrich_alert", "enrich_alerts_batch"]
