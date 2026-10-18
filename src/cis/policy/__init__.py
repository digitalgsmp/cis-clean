"""Closed MASTER/TASK policy compilation and append-only envelope authority.

The compiler is pure and cannot write. The authority is its single durable
owner and returns only an integrity- and staleness-verified envelope. Nothing
is re-exported here so callers must name which side of that boundary they use.
"""
