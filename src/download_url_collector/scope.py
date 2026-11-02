"""Crawl scope: which pages may be crawled and which links may be verified."""

from __future__ import annotations

from dataclasses import dataclass

from .config import ScopeConfig
from .urls import hostname, registrable_domain


@dataclass(frozen=True)
class Scope:
    seed_host: str
    seed_domain: str
    include_subdomains: bool
    additional_domains: frozenset[str]
    verify_external_downloads: bool
    follow_external_redirects: bool

    @classmethod
    def for_seed(cls, seed_url: str, cfg: ScopeConfig) -> Scope:
        host = hostname(seed_url)
        return cls(
            seed_host=host,
            seed_domain=registrable_domain(host),
            include_subdomains=cfg.include_subdomains,
            additional_domains=frozenset(d.lower().strip(".") for d in cfg.additional_domains),
            verify_external_downloads=cfg.verify_external_downloads,
            follow_external_redirects=cfg.follow_external_redirects,
        )

    def in_crawl_scope(self, url: str) -> bool:
        """Pages that may be fetched and parsed for further links."""
        host = hostname(url)
        if host == self.seed_host:
            return True
        if self.include_subdomains and registrable_domain(host) == self.seed_domain:
            return True
        for dom in self.additional_domains:
            if host == dom or host.endswith("." + dom):
                return True
        return False

    def crawl_redirect_reason(self, url: str) -> str | None:
        """Redirect hops while fetching *pages* must stay in crawl scope."""
        return None if self.in_crawl_scope(url) else "redirect_out_of_crawl_scope"

    def verify_redirect_reason(self, url: str) -> str | None:
        """Redirect hops while probing/verifying *candidates*."""
        if self.in_crawl_scope(url) or self.follow_external_redirects:
            return None
        return "redirect_out_of_scope"
