"""Operational knowledge: deterministic ingestion, governed retrieval and citations.

Everything this package stores or returns is ``RETRIEVED`` provenance. Persistence does not
change that, embedding does not change it, and a high similarity score does not change it.
Content leaves this package only as bounded untrusted text, and authorization - tenant,
scope, access labels, lifecycle - is decided in SQL before any content is ranked.

Retrieval reaches the investigation only through the Tool Broker's ``read.knowledge``
capability (:mod:`asic.knowledge.provider`); there is no second egress path.
"""
