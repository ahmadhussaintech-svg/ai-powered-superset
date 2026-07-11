#!/usr/bin/env python3
#
# Licensed to the Apache Software Foundation (ASF) under one or more
# contributor license agreements.  See the NOTICE file distributed with
# this work for additional information regarding copyright ownership.
# The ASF licenses this file to You under the Apache License, Version 2.0
# (the "License"); you may not use this file except in compliance with
# the License.  You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
"""Build a daily/weekly effectiveness report for the vulnerability workflow.

The script maintains a small JSON state file (persisted across runs via the
GitHub Actions cache) that stamps each CRITICAL finding with a first-seen
timestamp. This lets it compute remediation latency (MTTR), backlog aging and
flow metrics purely from the scan history -- without depending on any PR
convention. PR-based metrics (remediation PRs, straight-through, rework) are
derived from the GitHub API and rely on the `security` label convention; when
they cannot be computed they are reported as "n/a" rather than guessed.
"""

from __future__ import annotations

import argparse
import json  # noqa: TID251  # stdlib script; superset.utils.json is unavailable here
import os
import statistics
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

SLA_DAYS = 7  # remediation SLA for CRITICAL findings


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


def parse_iso(value: str) -> datetime:
    dt = datetime.fromisoformat(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def finding_key(cve: str, pkg: str, version: str, target: str) -> str:
    return f"{cve}|{pkg}|{version}|{target}"


@dataclass
class State:
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    resolved: list[dict[str, Any]] = field(default_factory=list)

    @classmethod
    def load(cls, path: str) -> "State":
        if not os.path.exists(path):
            return cls()
        with open(path, encoding="utf-8") as handle:
            data = json.load(handle)
        return cls(
            findings=data.get("findings", {}),
            resolved=data.get("resolved", []),
        )

    def save(self, path: str) -> None:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w", encoding="utf-8") as handle:
            json.dump(
                {"findings": self.findings, "resolved": self.resolved},
                handle,
                indent=2,
                sort_keys=True,
            )


def load_current_findings(trivy_path: str) -> dict[str, dict[str, Any]]:
    """Extract CRITICAL findings from a Trivy JSON report."""
    if not os.path.exists(trivy_path):
        return {}
    with open(trivy_path, encoding="utf-8") as handle:
        report = json.load(handle)

    findings: dict[str, dict[str, Any]] = {}
    for result in report.get("Results") or []:
        target = result.get("Target", "unknown")
        rtype = result.get("Type", "")
        for vuln in result.get("Vulnerabilities") or []:
            if vuln.get("Severity") != "CRITICAL":
                continue
            cve = vuln.get("VulnerabilityID", "UNKNOWN")
            pkg = vuln.get("PkgName", "unknown")
            version = vuln.get("InstalledVersion", "unknown")
            key = finding_key(cve, pkg, version, target)
            findings[key] = {
                "cve": cve,
                "pkg": pkg,
                "version": version,
                "target": target,
                "type": rtype,
                "fixed_version": vuln.get("FixedVersion"),
                "primary_url": vuln.get("PrimaryURL"),
            }
    return findings


def reconcile(
    state: State,
    current: dict[str, dict[str, Any]],
    now: datetime,
) -> tuple[list[str], list[dict[str, Any]], int]:
    """Update state with the current scan.

    Returns (new_keys, resolved_now, recurrences).
    """
    now_iso = now.isoformat()
    previous_keys = set(state.findings)
    current_keys = set(current)

    new_keys = sorted(current_keys - previous_keys)
    resolved_keys = sorted(previous_keys - current_keys)
    resolved_lookup = {r["key"]: r for r in state.resolved}

    recurrences = 0
    for key in new_keys:
        meta = dict(current[key])
        meta["first_seen"] = now_iso
        meta["last_seen"] = now_iso
        if key in resolved_lookup:
            # Previously fixed and now back -> regression / recurrence.
            recurrences += 1
            meta["reopened"] = resolved_lookup[key].get("reopened", 0) + 1
        state.findings[key] = meta

    for key in current_keys & previous_keys:
        state.findings[key]["last_seen"] = now_iso

    resolved_now: list[dict[str, Any]] = []
    for key in resolved_keys:
        meta = state.findings.pop(key)
        record = {
            "key": key,
            "cve": meta.get("cve"),
            "pkg": meta.get("pkg"),
            "version": meta.get("version"),
            "target": meta.get("target"),
            "first_seen": meta.get("first_seen", now_iso),
            "resolved_at": now_iso,
            "reopened": meta.get("reopened", 0),
        }
        state.resolved.append(record)
        resolved_now.append(record)

    return new_keys, resolved_now, recurrences


def age_days(first_seen: str, now: datetime) -> float:
    return (now - parse_iso(first_seen)).total_seconds() / 86400.0


def ttr_days(record: dict[str, Any]) -> float:
    return (
        parse_iso(record["resolved_at"]) - parse_iso(record["first_seen"])
    ).total_seconds() / 86400.0


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    rank = (pct / 100.0) * (len(ordered) - 1)
    low = int(rank)
    high = min(low + 1, len(ordered) - 1)
    frac = rank - low
    return ordered[low] + (ordered[high] - ordered[low]) * frac


@dataclass
class GitHub:
    repo: str
    token: str | None

    def _get(self, url: str) -> Any:
        if not url.startswith("https://api.github.com/"):
            raise ValueError(f"refusing to fetch non-GitHub URL: {url}")
        req = urllib.request.Request(url)  # noqa: S310  # scheme validated above
        req.add_header("Accept", "application/vnd.github+json")
        req.add_header("X-GitHub-Api-Version", "2022-11-28")
        if self.token:
            req.add_header("Authorization", f"Bearer {self.token}")
        with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
            return json.loads(resp.read().decode("utf-8"))

    def search_pr_count(self, qualifier: str) -> int:
        query = f"repo:{self.repo} is:pr label:security {qualifier}"
        url = "https://api.github.com/search/issues?q=" + urllib.parse.quote(query)
        return int(self._get(url).get("total_count", 0))

    def search_prs(self, qualifier: str) -> list[dict[str, Any]]:
        query = f"repo:{self.repo} is:pr label:security {qualifier}"
        url = (
            "https://api.github.com/search/issues?per_page=100&q="
            + urllib.parse.quote(query)
        )
        return self._get(url).get("items", [])

    def reviews(self, pr_number: int) -> list[dict[str, Any]]:
        url = (
            f"https://api.github.com/repos/{self.repo}/pulls/{pr_number}"
            "/reviews?per_page=100"
        )
        return self._get(url)


def pr_metrics(gh: GitHub, window_start: datetime) -> dict[str, Any]:
    """Remediation-PR metrics based on the `security` label convention.

    Returns counts, or `available=False` when the API is not reachable.
    """
    date = window_start.date().isoformat()
    try:
        opened = gh.search_pr_count(f"created:>={date}")
        merged_prs = gh.search_prs(f"merged:>={date}")
    except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
        return {"available": False}

    straight_through = 0
    rework = 0
    for pr in merged_prs:
        try:
            reviews = gh.reviews(pr["number"])
        except (urllib.error.URLError, urllib.error.HTTPError, ValueError):
            continue
        human_changes = any(
            r.get("state") == "CHANGES_REQUESTED"
            and (r.get("user") or {}).get("type") != "Bot"
            for r in reviews
        )
        if human_changes:
            # A human asked for changes before the fix merged.
            rework += 1
        else:
            # Merged without any human requesting changes -> straight-through.
            straight_through += 1

    merged = len(merged_prs)
    return {
        "available": True,
        "opened": opened,
        "merged": merged,
        "straight_through": straight_through,
        "rework": rework,
        "rework_rate": (rework / merged) if merged else 0.0,
    }


def compute_aging(
    findings: dict[str, dict[str, Any]], now: datetime
) -> tuple[dict[str, int], int]:
    buckets = {"0-7d": 0, "8-30d": 0, ">30d": 0}
    sla_breaching = 0
    for meta in findings.values():
        age = age_days(meta["first_seen"], now)
        if age <= 7:
            buckets["0-7d"] += 1
        elif age <= 30:
            buckets["8-30d"] += 1
        else:
            buckets[">30d"] += 1
        if age > SLA_DAYS:
            sla_breaching += 1
    return buckets, sla_breaching


def _section_flow(
    new_count: int, resolved_count: int, total_open: int, recurrences: int
) -> list[str]:
    lines = [
        "*Critical vulnerabilities*",
        f"• New (in window): *{new_count}*",
        f"• Resolved (in window): *{resolved_count}*",
        f"• Currently open (backlog): *{total_open}*",
    ]
    if recurrences:
        lines.append(f"• :warning: Recurrences (regressed): *{recurrences}*")
    lines.append("")
    return lines


def _section_speed(ttrs: list[float]) -> list[str]:
    lines = ["*Remediation speed (resolved in window)*"]
    if ttrs:
        coverage = len([t for t in ttrs if t <= SLA_DAYS]) / len(ttrs) * 100.0
        lines.append(
            f"• MTTR median: *{statistics.median(ttrs):.1f}d*  "
            f"|  p90: *{percentile(ttrs, 90):.1f}d*"
        )
        lines.append(f"• Resolved within {SLA_DAYS}d SLA: *{coverage:.0f}%*")
    else:
        lines.append("• No findings resolved in window (MTTR n/a)")
    lines.append("")
    return lines


def _section_prs(prs: dict[str, Any]) -> list[str]:
    lines = ["*Remediation PRs (label:security)*"]
    if prs.get("available"):
        lines.append(f"• Opened in window: *{prs['opened']}*")
        lines.append(
            f"• Merged: *{prs['merged']}*  "
            f"|  straight-through: *{prs['straight_through']}*"
            f"  |  required rework: *{prs['rework']}*"
        )
        if prs["merged"]:
            straight_rate = prs["straight_through"] / prs["merged"] * 100
            lines.append(
                f"• Straight-through rate: *{straight_rate:.0f}%*  "
                f"|  rework rate: *{prs['rework_rate'] * 100:.0f}%*"
            )
    else:
        lines.append("• n/a (GitHub API unavailable or no `security`-labelled PRs)")
    lines.append("")
    return lines


def _section_new(new_keys: list[str], findings: dict[str, dict[str, Any]]) -> list[str]:
    if not new_keys:
        return []
    lines = ["*Newly discovered this window*"]
    for key in new_keys[:10]:
        meta = findings.get(key, {})
        lines.append(
            f"• `{meta.get('pkg')}` {meta.get('version')} — "
            f"{meta.get('cve')} ({meta.get('target')})"
        )
    if len(new_keys) > 10:
        lines.append(f"• …and {len(new_keys) - 10} more")
    lines.append("")
    return lines


def build_report(
    *,
    mode: str,
    state: State,
    new_keys: list[str],
    recurrences: int,
    now: datetime,
    window_days: int,
    prs: dict[str, Any],
    run_url: str,
    repo: str,
) -> str:
    window_start = now - timedelta(days=window_days)
    new_in_window = [
        m for m in state.findings.values() if parse_iso(m["first_seen"]) >= window_start
    ]
    resolved_in_window = [
        r for r in state.resolved if parse_iso(r["resolved_at"]) >= window_start
    ]
    buckets, sla_breaching = compute_aging(state.findings, now)
    ttrs = [ttr_days(r) for r in resolved_in_window]

    label = "Daily" if mode == "daily" else "Weekly"
    lines = [
        f":bar_chart: *{label} vulnerability remediation report — `{repo}`*  "
        f"({now.date().isoformat()} UTC, last {window_days}d)",
        "",
    ]
    lines += _section_flow(
        len(new_in_window), len(resolved_in_window), len(state.findings), recurrences
    )
    lines += [
        "*Backlog aging*",
        f"• 0–7d: {buckets['0-7d']}  |  8–30d: {buckets['8-30d']}  "
        f"|  >30d: {buckets['>30d']}",
        f"• Breaching {SLA_DAYS}d SLA: *{sla_breaching}*",
        "",
    ]
    lines += _section_speed(ttrs)
    lines += _section_prs(prs)
    lines += _section_new(new_keys, state.findings)
    lines.append(f"<{run_url}|View workflow run>")
    return "\n".join(lines)


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--trivy", required=True, help="Path to Trivy JSON report")
    parser.add_argument("--state", required=True, help="Path to state JSON file")
    parser.add_argument("--mode", choices=["daily", "weekly"], default="daily")
    parser.add_argument("--output", required=True, help="Slack payload output path")
    args = parser.parse_args()

    repo = os.environ.get("GITHUB_REPOSITORY", "unknown/unknown")
    server = os.environ.get("GITHUB_SERVER_URL", "https://github.com")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    run_url = f"{server}/{repo}/actions/runs/{run_id}" if run_id else server
    window_days = 1 if args.mode == "daily" else 7

    now = now_utc()
    state = State.load(args.state)
    current = load_current_findings(args.trivy)
    new_keys, _resolved_now, recurrences = reconcile(state, current, now)

    gh = GitHub(repo=repo, token=os.environ.get("GITHUB_TOKEN"))
    prs = pr_metrics(gh, now - timedelta(days=window_days))

    text = build_report(
        mode=args.mode,
        state=state,
        new_keys=new_keys,
        recurrences=recurrences,
        now=now,
        window_days=window_days,
        prs=prs,
        run_url=run_url,
        repo=repo,
    )

    state.save(args.state)
    with open(args.output, "w", encoding="utf-8") as handle:
        json.dump({"text": text}, handle)

    print(text)


if __name__ == "__main__":
    main()
