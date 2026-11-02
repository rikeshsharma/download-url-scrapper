"""Dataset metadata: grouping, leakage-safe splits and temporal ordering.

Grouping
* Identical payloads (same SHA-256) always land in the same split.
* Unseen-domain evaluation groups by a *publisher domain*: the adapter
  publisher if known, else the registrable domain of the seed (the site that
  linked the file). The final download host is not used for grouping because
  shared CDNs / object stores (e.g. one storage host serving thousands of
  publishers) would merge unrelated publishers into one giant group, while
  one publisher using several CDNs would be split across groups.
* Payload hashes and publisher domains form a bipartite graph; connected
  components are assigned to splits as a unit, so a payload seen under two
  publishers cannot leak between unseen-domain train and test.
"""

from __future__ import annotations

import hashlib
from collections import defaultdict
from dataclasses import dataclass
from typing import Any


def _bucket(key: str, salt: str) -> float:
    h = hashlib.sha256(f"{salt}:{key}".encode()).digest()
    return int.from_bytes(h[:8], "big") / 2**64


class _UnionFind:
    def __init__(self) -> None:
        self.parent: dict[str, str] = {}

    def find(self, x: str) -> str:
        self.parent.setdefault(x, x)
        while self.parent[x] != x:
            self.parent[x] = self.parent[self.parent[x]]
            x = self.parent[x]
        return x

    def union(self, a: str, b: str) -> None:
        ra, rb = self.find(a), self.find(b)
        if ra != rb:
            self.parent[max(ra, rb)] = min(ra, rb)


@dataclass
class SampleMeta:
    observation_id: str
    sha256: str
    group_domain: str
    first_seen: str
    payload_split: str
    unseen_domain_split: str
    temporal_split: str | None
    component_id: str


def assign_splits(samples: list[dict[str, Any]], *, test_fraction: float, unseen_fraction: float,
                  salt: str, temporal_cutoff: str | None) -> list[SampleMeta]:
    """samples: dicts with observation_id, sha256, group_domain, first_seen."""
    uf = _UnionFind()
    for s in samples:
        uf.union("h:" + s["sha256"], "d:" + s["group_domain"])
    comp_domains: dict[str, set[str]] = defaultdict(set)
    for s in samples:
        comp_domains[uf.find("h:" + s["sha256"])].add(s["group_domain"])
    out: list[SampleMeta] = []
    for s in samples:
        comp = uf.find("h:" + s["sha256"])
        payload = "test" if _bucket("h:" + s["sha256"], salt) < test_fraction else "train"
        unseen = "unseen_domain_test" if _bucket("c:" + comp, salt) < unseen_fraction else "train"
        temporal = None
        if temporal_cutoff:
            temporal = "temporal_test" if s["first_seen"] >= temporal_cutoff else "train"
        out.append(SampleMeta(s["observation_id"], s["sha256"], s["group_domain"], s["first_seen"],
                              payload, unseen, temporal, hashlib.sha256(comp.encode()).hexdigest()[:12]))
    return out
