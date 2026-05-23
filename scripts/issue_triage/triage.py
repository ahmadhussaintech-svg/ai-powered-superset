# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.
"""
Upstream Issue Triage System

Polls new issues from apache/superset, classifies them by severity using an LLM,
and sends Slack notifications for P0 issues.
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

import requests
from openai import OpenAI

UPSTREAM_REPO = "apache/superset"
STATE_FILE = Path(__file__).parent / ".last_poll_timestamp"
GITHUB_API = "https://api.github.com"

CLASSIFICATION_PROMPT = (
    "You are a software issue triage specialist for Apache "
    "Superset, a business intelligence web application. "
    "Classify the following GitHub issue by severity.\n\n"
    "Priority levels:\n"
    "- P0: Production outages, data loss/corruption, security "
    "vulnerabilities, complete feature breakage affecting "
    "all/most users, authentication/authorization bypass\n"
    "- P1: Major feature broken for a subset of users, "
    "significant performance degradation (>5x slower), "
    "blocking regressions in recent releases, data integrity "
    "issues with limited scope\n"
    "- P2: Non-critical bugs with workarounds available, "
    "moderate UX issues, minor performance degradation, "
    "edge-case failures\n"
    "- P3: Enhancement requests, cosmetic/styling issues, "
    "documentation gaps, developer experience improvements, "
    "nice-to-haves\n\n"
    "Respond with a JSON object containing:\n"
    '- "priority": "P0" | "P1" | "P2" | "P3"\n'
    '- "reasoning": A 1-2 sentence explanation of why this '
    "priority was assigned\n"
    '- "resolution_path": For P0/P1 only - a brief suggested '
    "resolution approach (2-3 sentences)\n"
    '- "affected_area": The Superset subsystem affected '
    '(e.g., "SQL Lab", "Dashboard", "Charts", "Security", '
    '"API", "Database Connectivity", "Authentication", '
    '"Frontend", "Backend")\n\n'
    "Issue Title: {title}\n\n"
    "Issue Body:\n"
    "{body}\n\n"
    "Issue Labels: {labels}\n"
)

SLACK_MESSAGE_TEMPLATE = """
:rotating_light: *P0 Issue Detected in apache/superset* :rotating_light:

*Title:* <{url}|{title}>
*Author:* {author}
*Created:* {created_at}
*Labels:* {labels}
*Affected Area:* {affected_area}

*Summary:*
{reasoning}

*Suggested Resolution Path:*
{resolution_path}

---
_Classified automatically by issue triage bot_
"""


def get_last_poll_time() -> str:
    """Get the last poll timestamp, defaulting to 15 minutes ago."""
    if STATE_FILE.exists():
        return STATE_FILE.read_text().strip()
    dt = datetime.now(timezone.utc) - timedelta(minutes=15)
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


def save_poll_time(timestamp: str) -> None:
    """Save the given poll timestamp to the state file."""
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(timestamp)


def fetch_new_issues(since: str) -> list[dict[str, Any]]:
    """Fetch issues created since the given timestamp from upstream repo."""
    headers: dict[str, str] = {"Accept": "application/vnd.github+json"}
    if token := os.environ.get("GH_TOKEN"):
        headers["Authorization"] = f"Bearer {token}"

    issues: list[dict[str, Any]] = []
    page = 1
    while True:
        resp = requests.get(
            f"{GITHUB_API}/repos/{UPSTREAM_REPO}/issues",
            headers=headers,
            params={
                "state": "open",
                "since": since,
                "sort": "created",
                "direction": "desc",
                "per_page": str(100),
                "page": str(page),
            },
            timeout=30,
        )
        resp.raise_for_status()
        batch: list[dict[str, Any]] = resp.json()
        if not batch:
            break
        for issue in batch:
            if "pull_request" in issue:
                continue
            if issue["created_at"] > since:
                issues.append(issue)
        page += 1
        if len(batch) < 100:
            break

    return issues


def classify_issue(issue: dict[str, Any]) -> dict[str, str]:
    """Use OpenAI to classify the issue severity."""
    client = OpenAI(api_key=os.environ["OPENAI_API_KEY"])

    title: str = issue["title"]
    body: str = (issue.get("body") or "")[:3000]
    labels: str = ", ".join(label["name"] for label in issue.get("labels", []))

    prompt = CLASSIFICATION_PROMPT.format(title=title, body=body, labels=labels)

    response = client.chat.completions.create(
        model="gpt-4o",
        messages=[{"role": "user", "content": prompt}],
        response_format={"type": "json_object"},
        temperature=0.1,
    )

    content = response.choices[0].message.content or "{}"
    result: dict[str, str] = json.loads(content)
    return result


def send_slack_alert(issue: dict[str, Any], classification: dict[str, str]) -> None:
    """Send a Slack notification for P0 issues."""
    webhook_url = os.environ["SLACK_WEBHOOK_URL"]

    labels = ", ".join(label["name"] for label in issue.get("labels", [])) or "None"

    message = SLACK_MESSAGE_TEMPLATE.format(
        url=issue["html_url"],
        title=issue["title"],
        author=issue["user"]["login"],
        created_at=issue["created_at"],
        labels=labels,
        affected_area=classification.get("affected_area", "Unknown"),
        reasoning=classification.get("reasoning", ""),
        resolution_path=classification.get("resolution_path", "To be determined"),
    )

    payload = {"text": message, "unfurl_links": False}
    resp = requests.post(webhook_url, json=payload, timeout=15)
    resp.raise_for_status()
    print(f"  -> Slack alert sent for: {issue['title']}")


def main() -> None:
    since = get_last_poll_time()
    print(f"Polling issues since: {since}")

    issues = fetch_new_issues(since)
    print(f"Found {len(issues)} new issue(s)")

    if not issues:
        now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        save_poll_time(now)
        return

    for issue in issues:
        print(f"\nClassifying: #{issue['number']} - {issue['title']}")
        try:
            classification = classify_issue(issue)
            priority = classification.get("priority", "P3")
            print(f"  Priority: {priority} - {classification.get('reasoning', '')}")

            if priority == "P0":
                send_slack_alert(issue, classification)

        except Exception as e:
            print(
                f"  ERROR classifying issue #{issue['number']}: {e}",
                file=sys.stderr,
            )
            continue

        # Rate limit courtesy
        time.sleep(1)

    latest = max(issue["created_at"] for issue in issues)
    save_poll_time(latest)
    print(f"\nDone. Next poll will start from: {latest}")


if __name__ == "__main__":
    main()
