"""Exercise release retry and moving-tag decisions without publishing anything."""

import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

WORKFLOWS = Path(__file__).parents[1] / ".github" / "workflows"
pytestmark = pytest.mark.skipif(shutil.which("bash") is None, reason="requires bash")


def workflow_script(filename, step_name):
    workflow = yaml.safe_load((WORKFLOWS / filename).read_text())
    for job in workflow["jobs"].values():
        for step in job.get("steps", []):
            if step.get("name") == step_name:
                return step["run"]
    raise AssertionError(f"Missing workflow step: {step_name}")


@pytest.mark.parametrize(
    ("branch", "existing", "expected"),
    [
        ("feature/container", "", "v1.3.0"),
        ("fix/container", "", "v1.2.4"),
        ("major/container", "", "v2.0.0"),
        ("feature/container", "v1.2.1", "v1.2.1"),
        ("unreleased/container", "", ""),
    ],
)
def test_release_version_and_retry(tmp_path, branch, existing, expected):
    script = workflow_script("release-on-merge.yml", "Determine release version")
    stub = """
git() {
    if [[ "$1" == fetch ]]; then return; fi
    if [[ "$1" == push ]]; then echo pushed >> "$TRACE"; return; fi
    if [[ "$1" == tag && "$2" == --points-at ]]; then
        printf '%s\\n' "$EXISTING_TAG"; return
    fi
    if [[ "$1" == tag && "$2" == --sort=v:refname ]]; then
        printf '%s\\n' v1.0.0 v1.2.3 v9.0.0rc1 unrelated; return
    fi
    echo tagged >> "$TRACE"
}
"""
    output = tmp_path / "output"
    trace = tmp_path / "trace"
    env = dict(os.environ, BRANCH_NAME=branch, EXISTING_TAG=existing,
               GITHUB_OUTPUT=str(output), TRACE=str(trace))
    subprocess.run(["bash", "-e", "-o", "pipefail", "-c", stub + script],
                   env=env, check=True, capture_output=True, text=True)
    assert (output.read_text().strip() if output.exists() else "") == (
        f"new_version={expected}" if expected else ""
    )
    assert trace.exists() == bool(expected and not existing)


@pytest.mark.parametrize(("release", "updates"), [("v1.2.3", False), ("v1.3.0", True)])
def test_latest_alias_never_moves_to_older_release(tmp_path, release, updates):
    script = workflow_script("publish-container.yml", "Update latest alias for newest release")
    trace = tmp_path / "trace"
    stub = """
git() {
    printf '%s\\n' 'hash refs/tags/v1.2.3' 'hash refs/tags/v1.3.0' 'hash refs/tags/v9.0.0rc1'
}
docker() { printf '%s\\n' "$*" > "$TRACE"; }
"""
    env = dict(os.environ, RELEASE_TAG=release, TRACE=str(trace),
               VERSIONED_TAG="example:1.3.0", LATEST_TAG="example:latest")
    subprocess.run(["bash", "-e", "-o", "pipefail", "-c", stub + script],
                   env=env, check=True, capture_output=True, text=True)
    assert trace.exists() == updates
    if updates:
        assert "imagetools create --tag example:latest example:1.3.0" in trace.read_text()
