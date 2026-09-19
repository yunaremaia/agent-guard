"""Regression tests for the checked-in policy templates."""

from pathlib import Path

from agent_guard import Action, Policy


POLICY_DIR = Path(__file__).parents[1] / "examples" / "policies"
EXPECTED_POLICIES = {
    "ci-agent.yaml": "ci-agent",
    "custom-tool.yaml": "custom-tool",
    "full-access.yaml": "full-access",
    "read-only.yaml": "read-only",
    "sandboxed.yaml": "sandboxed",
}


def test_all_policy_templates_parse() -> None:
    templates = {path.name: path for path in POLICY_DIR.glob("*.yaml")}

    assert templates.keys() == EXPECTED_POLICIES.keys()
    for filename, expected_name in EXPECTED_POLICIES.items():
        policy = Policy.from_file(templates[filename])
        assert policy.name == expected_name
        assert policy.default_action in {Action.ALLOW, Action.DENY}
        assert policy.rules


def test_templates_are_bounded_by_default_action() -> None:
    for path in POLICY_DIR.glob("*.yaml"):
        policy = Policy.from_file(path)
        assert policy.default_action == Action.DENY or path.name == "full-access.yaml"
