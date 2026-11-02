"""Command-line interface (``duc`` / ``download-url-collector``)."""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path
from typing import Any

import click

from . import __version__
from .browser.environment import BrowserUnavailable
from .config import Config, load_config
from .crawler import sensitivity
from .inputs import SeedFileError
from .logging_setup import setup_logging


class Ctx:
    def __init__(self, cfg: Config) -> None:
        self.cfg = cfg
        from .pipeline import open_store

        self.store = open_store(cfg)

    def run_id(self, run_id: str | None) -> str:
        rid = run_id or self.store.latest_run_id()
        if not rid or self.store.get_run(rid) is None:
            raise click.UsageError(f"unknown run: {run_id or '(no runs yet)'}")
        return rid


def _run(coro: Any) -> Any:
    try:
        return asyncio.run(coro)
    except BrowserUnavailable as exc:
        click.echo(f"error: browser unavailable: {exc}", err=True)
        sys.exit(3)


@click.group()
@click.version_option(__version__)
@click.option("--config", "-c", "config_path", type=click.Path(exists=True, dir_okay=False),
              help="YAML configuration file.")
@click.option("--log-level", default="INFO", show_default=True)
@click.option("--log-file", type=click.Path(dir_okay=False), default=None)
@click.pass_context
def main(ctx: click.Context, config_path: str | None, log_level: str, log_file: str | None) -> None:
    """Discover, browser-verify, inspect and label download URLs.

    Verified downloads are NOT assumed benign; see `duc label`.
    """
    try:
        cfg = load_config(config_path)
    except (ValueError, OSError) as exc:
        raise click.ClickException(f"invalid configuration: {exc}") from exc
    setup_logging(log_level, sensitivity(cfg), log_file)
    ctx.obj = Ctx(cfg)


@main.command()
@click.argument("seeds", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--run-id", default=None, help="Explicit run id (default: generated).")
@click.pass_obj
def crawl(obj: Ctx, seeds: Path, run_id: str | None) -> None:
    """Create a run from a seed CSV and run discovery + HTTP probing."""
    from .pipeline import crawl as do_crawl
    from .pipeline import start_run

    try:
        rid = start_run(obj.cfg, obj.store, seeds, run_id)
    except SeedFileError as exc:
        raise click.ClickException(str(exc)) from exc
    _run(do_crawl(obj.cfg, obj.store, rid))
    click.echo(rid)


@main.command()
@click.option("--run-id", default=None, help="Run to verify (default: latest).")
@click.pass_obj
def verify(obj: Ctx, run_id: str | None) -> None:
    """Browser-verify candidates of a run (direct navigation + recorded interactions)."""
    from .pipeline import verify as do_verify

    _run(do_verify(obj.cfg, obj.store, obj.run_id(run_id)))


@main.command()
@click.option("--run-id", default=None)
@click.option("--force", is_flag=True, help="Re-collect evidence even if fresh evidence exists.")
@click.pass_obj
def label(obj: Ctx, run_id: str | None, force: bool) -> None:
    """Collect evidence and apply the versioned labeling policy."""
    from .pipeline import label as do_label

    counts = _run(do_label(obj.cfg, obj.store, obj.run_id(run_id), force))
    click.echo(json.dumps(counts, sort_keys=True))


@main.command()
@click.option("--sha256", required=True)
@click.option("--verdict", type=click.Choice(["benign", "suspicious", "malicious"]), required=True)
@click.option("--reviewer", required=True)
@click.option("--notes", default="")
@click.pass_obj
def review(obj: Ctx, sha256: str, verdict: str, reviewer: str, notes: str) -> None:
    """Record a manual review verdict as evidence (re-run `label` afterwards)."""
    from .labeling.labeler import add_manual_review

    try:
        click.echo(add_manual_review(obj.store, sha256.lower(), verdict, reviewer, notes))
    except (KeyError, ValueError) as exc:
        raise click.ClickException(str(exc)) from exc


@main.command()
@click.option("--run-id", default=None)
@click.option("--limit", type=int, default=None, help="Maximum URLs to revalidate.")
@click.option("--relabel/--no-relabel", default=True)
@click.pass_obj
def revalidate(obj: Ctx, run_id: str | None, limit: int | None, relabel: bool) -> None:
    """Re-verify direct-download URLs; changed content becomes a new observation."""
    from .pipeline import label as do_label
    from .pipeline import revalidate as do_reval

    rid = obj.run_id(run_id)
    stats = _run(do_reval(obj.cfg, obj.store, rid, limit))
    if relabel:
        _run(do_label(obj.cfg, obj.store, rid))
    click.echo(json.dumps(stats, sort_keys=True))


@main.command()
@click.option("--run-id", default=None)
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path), default=None)
@click.pass_obj
def export(obj: Ctx, run_id: str | None, out_dir: Path | None) -> None:
    """Write CSV/JSONL outputs."""
    from .export import Exporter

    rid = obj.run_id(run_id)
    out = out_dir or obj.cfg.collection.data_dir / "exports" / rid
    counts = Exporter(obj.cfg, obj.store, rid, out).run()
    click.echo(json.dumps({"out_dir": str(out), "rows": counts}, sort_keys=True))


@main.command()
@click.option("--run-id", default=None)
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path), default=None)
@click.pass_obj
def report(obj: Ctx, run_id: str | None, out_dir: Path | None) -> None:
    """Write coverage_report.json and coverage_summary.md (redacted, shareable)."""
    from .report import write_report

    rid = obj.run_id(run_id)
    out = out_dir or obj.cfg.collection.data_dir / "exports" / rid
    write_report(obj.cfg, obj.store, rid, out)
    click.echo((out / "coverage_summary.md").read_text())


@main.command()
@click.option("--run-id", default=None)
@click.option("--no-browser", is_flag=True, help="Only resume discovery/probing.")
@click.pass_obj
def resume(obj: Ctx, run_id: str | None, no_browser: bool) -> None:
    """Resume an interrupted run (unfinished pages, probes, and verifications)."""
    from .pipeline import resume as do_resume

    _run(do_resume(obj.cfg, obj.store, obj.run_id(run_id), with_browser=not no_browser))


@main.command()
@click.argument("seeds", type=click.Path(exists=True, dir_okay=False, path_type=Path))
@click.option("--out", "out_dir", type=click.Path(file_okay=False, path_type=Path), default=None)
@click.pass_context
def run(ctx: click.Context, seeds: Path, out_dir: Path | None) -> None:
    """crawl → verify → label → export → report in one go."""
    obj: Ctx = ctx.obj
    from .export import Exporter
    from .pipeline import crawl as do_crawl
    from .pipeline import label as do_label
    from .pipeline import start_run
    from .pipeline import verify as do_verify
    from .report import write_report

    try:
        rid = start_run(obj.cfg, obj.store, seeds)
    except SeedFileError as exc:
        raise click.ClickException(str(exc)) from exc
    _run(do_crawl(obj.cfg, obj.store, rid))
    _run(do_verify(obj.cfg, obj.store, rid))
    _run(do_label(obj.cfg, obj.store, rid))
    out = out_dir or obj.cfg.collection.data_dir / "exports" / rid
    Exporter(obj.cfg, obj.store, rid, out).run()
    write_report(obj.cfg, obj.store, rid, out)
    click.echo(json.dumps({"run_id": rid, "out_dir": str(out)}))


@main.command("browser-info")
@click.pass_obj
def browser_info(obj: Ctx) -> None:
    """Launch the configured browser and print its recorded identity."""
    from playwright.async_api import async_playwright

    from .browser.environment import launch

    async def go() -> dict[str, Any]:
        async with async_playwright() as pw:
            browser, ident = await launch(pw, obj.cfg.browser)
            await browser.close()
            return ident.to_dict()

    click.echo(json.dumps(_run(go()), indent=2))


@main.command("runs")
@click.pass_obj
def runs(obj: Ctx) -> None:
    """List runs."""
    for r in obj.store.query("SELECT run_id, created_at, status FROM runs ORDER BY created_at"):
        click.echo(f"{r['run_id']}\t{r['created_at']}\t{r['status']}")


if __name__ == "__main__":  # pragma: no cover
    main()
