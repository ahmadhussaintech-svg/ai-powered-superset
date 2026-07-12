<!--
Licensed to the Apache Software Foundation (ASF) under one
or more contributor license agreements.  See the NOTICE file
distributed with this work for additional information
regarding copyright ownership.  The ASF licenses this file
to you under the Apache License, Version 2.0 (the
"License"); you may not use this file except in compliance
with the License.  You may obtain a copy of the License at

  http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing,
software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
KIND, either express or implied.  See the License for the
specific language governing permissions and limitations
under the License.
-->

# Security: Vulnerability Scanning & Remediation Reporting

This repository runs an automated, defensive vulnerability workflow to detect
CRITICAL dependency vulnerabilities and to measure how effectively they are
remediated over time.

Two GitHub Actions workflows power this:

| Workflow | File | What it does |
| --- | --- | --- |
| **Vulnerability Scan** | [`.github/workflows/vulnerability-scan.yml`](../workflows/vulnerability-scan.yml) | Daily Trivy filesystem scan for CRITICAL findings; posts **one Slack message per finding** with description, why it's critical (CVSS score/vector) and the exploit path. |
| **Vulnerability Report** | [`.github/workflows/vulnerability-report.yml`](../workflows/vulnerability-report.yml) | Daily + weekly effectiveness report posted to Slack, computed by [`.github/scripts/vuln_report.py`](vuln_report.py). |

## What the effectiveness report measures

The report is designed to answer *"is the remediation process actually reducing
risk?"*, not just *"how many alerts did we send?"*. It tracks:

- **Flow** — new / resolved / currently-open CRITICAL findings, plus recurrences
  (a finding that reappears after being fixed).
- **Backlog aging** — open findings bucketed `0–7d` / `8–30d` / `>30d`, and how
  many breach the 7-day SLA.
- **Remediation speed** — MTTR (median + p90) and the share of findings resolved
  within the SLA. Computed purely from the scan history (a finding's
  first-seen → resolved timestamps), so it needs no PR metadata.
- **Remediation PRs** — opened / merged, plus **straight-through** vs.
  **rework** (see below). Attributed via the `security` label convention.

Findings are keyed by `CVE | package | installed-version | target-file`. A small
JSON state file is persisted across runs via the Actions cache to enable
day-over-day deltas and MTTR.

**Straight-through vs. rework:** a merged `security` PR is counted as
*straight-through* when no human requested changes on it (the agent's fix landed
without human intervention), and as *rework* when at least one human
`CHANGES_REQUESTED` review occurred before merge. The straight-through rate is
the headline measure of how autonomous the agent's remediations are.

## Running or simulating the workflows

Both workflows support manual runs and a daily/weekly schedule.

**Run in CI (manual dispatch):**

```bash
# Trigger the scan or the report on demand (mode: daily | weekly)
gh workflow run vulnerability-scan.yml
gh workflow run vulnerability-report.yml -f mode=weekly
```

Or use the **Actions** tab → select the workflow → **Run workflow**.

**Simulate the report locally** (no CI required):

```bash
# 1. Install Trivy (https://trivy.dev) and run a CRITICAL-only filesystem scan
trivy fs --scanners vuln --severity CRITICAL \
  --format json --output trivy-results.json .

# 2. Build the report; state.json persists first-seen timestamps across runs
mkdir -p .vuln-state
GITHUB_REPOSITORY="$(git config --get remote.origin.url | sed -E 's#.*/([^/]+/[^/]+)(\.git)?#\1#')" \
python3 .github/scripts/vuln_report.py \
  --trivy trivy-results.json \
  --state .vuln-state/state.json \
  --mode daily \
  --output report-payload.json

# 3. (Optional) Post it to Slack, exactly as CI does
curl -X POST -H 'Content-type: application/json' \
  --data @report-payload.json "$SLACK_WEBHOOK_URL"
```

Re-running step 2 against a *different* `trivy-results.json` (e.g. one with some
findings removed) simulates a day where vulnerabilities were remediated, so you
can see MTTR, SLA coverage, backlog aging and recurrence populate.

**Configuration:** set the `SLACK_WEBHOOK_URL` repository secret to a
`https://hooks.slack.com/services/...` incoming webhook. PR-based metrics use the
repository's `GITHUB_TOKEN` and require remediation PRs to carry the `security`
label.
