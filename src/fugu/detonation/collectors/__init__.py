"""Collector assets copied/mounted INTO detonation containers.

These files are not imported as a Python package at runtime — they are shipped
into the DNS-collector image (dns_collector.py) and bind-mounted read-only into
the mitmproxy container (mitm_addon.py). Adapted verbatim from the VALIDATED
spike at spikes/001-canary-egress/ (do not modify the spike).
"""
