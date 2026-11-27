"""The route table for tests/test_audit_route_coverage_r96.py: one entry per mutating route (B7).

Kept apart so the meta test stays small. ``exercised`` entries carry the request the scenario
sends (in table order, so a later entry may use an id an earlier one captured), ``proven``
entries name the test that asserts the row (it must contain the literal action string),
``exempt`` entries carry a reason.
"""

from dataclasses import dataclass, field
from typing import Any

SB = "/v1/sandboxes/{sandbox_id}"
TB = SB + "/toolbox"
SESSIONS = TB + "/process/sessions"


@dataclass(frozen=True)
class Entry:
    kind: str  # "exercised", "proven" or "exempt"
    action: str = ""  # the audit action the route writes (empty for exempt)
    proof: str = ""  # proven: "<test file>::<test function>"
    reason: str = ""  # exempt: why no row is written
    step: dict[str, Any] = field(default_factory=dict)  # exercised: how the scenario calls it


def exercised(action: str, status: int = 200, capture: str = "", **request: Any) -> Entry:
    """``capture`` is ``"<name>:<field>"``: keep ``data[<field>]`` for later ``{<name>}`` paths."""
    return Entry("exercised", action, step={"status": status, "capture": capture, **request})


def proven(action: str, proof: str) -> Entry:
    """The proof function must contain the literal action string, never a constant naming it."""
    return Entry("proven", action, proof=proof)


def exempt(reason: str) -> Entry:
    return Entry("exempt", reason=reason)


SESSIONS_PROOF = "test_toolbox_sessions.py::test_actions_are_audited_without_command_text_or_output"
CONTEXTS_PROOF = "test_code_contexts_api.py::test_every_mutating_call_is_audited_and_reads_are_not"
FS_PROOF = "test_toolbox_fs.py::test_every_operation_is_audited_without_contents"
SCIM_PROOF = "test_scim_auth.py::test_writes_are_audited_with_the_scim_token_as_actor"

COVERAGE: dict[tuple[str, str], Entry] = {
    ("POST", "/v1/sandboxes"): exercised("sandbox.create", 201, "sandbox_id:id", json={}),
    ("PATCH", SB): exercised("sandbox.update", json={"labels": {"team": "blue"}}),
    ("POST", SB + "/preview-tokens"): exercised(
        "sandbox.preview_token_created", 201, json={"port": 3000}
    ),
    ("POST", TB + "/process/execute"): exercised("toolbox.process.execute", json={"argv": ["ls"]}),
    ("POST", TB + "/process/code-run"): exercised(
        "toolbox.process.code_run", json={"language": "python", "code": "print(1)"}
    ),
    ("POST", TB + "/fs/mkdir"): exercised("toolbox.fs.mkdir", json={"path": "/work/n"}),
    ("PUT", TB + "/fs/upload"): exercised(
        "toolbox.fs.upload", params={"path": "/work/n/f.txt"}, content=b"hello"
    ),
    # The fake shell answers every stat with "exists", so a move meets its destination: proven.
    ("POST", TB + "/fs/move"): proven("toolbox.fs.move", FS_PROOF),
    ("POST", TB + "/fs/delete"): exercised("toolbox.fs.delete", json={"path": "/work/n"}),
    ("POST", TB + "/git/clone"): exercised(
        "toolbox.git.clone", json={"url": "https://example.com/r.git", "path": "/work/r"}
    ),
    ("POST", TB + "/git/status"): exercised("toolbox.git.status", json={"path": "/work/r"}),
    ("POST", TB + "/git/add"): exercised("toolbox.git.add", json={"path": "/work/r"}),
    ("POST", TB + "/git/commit"): exercised(
        "toolbox.git.commit", json={"path": "/work/r", "message": "m"}
    ),
    ("POST", TB + "/git/push"): exercised("toolbox.git.push", json={"path": "/work/r"}),
    ("POST", TB + "/git/pull"): exercised("toolbox.git.pull", json={"path": "/work/r"}),
    ("POST", TB + "/pty"): exercised("toolbox.pty.create", 201, "pty_id:pty_id", json={}),
    ("POST", TB + "/pty/{pty_id}/resize"): exercised(
        "toolbox.pty.resize", json={"rows": 30, "cols": 100}
    ),
    ("DELETE", TB + "/pty/{pty_id}"): exercised("toolbox.pty.close"),
    ("POST", SESSIONS): exercised("toolbox.session.create", 201, "session_id:id", json={}),
    ("DELETE", SESSIONS + "/{session_id}"): exercised("toolbox.session.delete"),
    ("POST", SB + "/stop"): exercised("sandbox.stop"),
    ("POST", SB + "/resize"): exercised("sandbox.resized", json={"disk_gib": 4}),
    ("POST", SB + "/start"): exercised("sandbox.start"),
    ("POST", SB + "/reset"): exercised("sandbox.reset"),
    ("DELETE", SB): exercised("sandbox.delete"),
    ("POST", "/v1/volumes"): exercised("volume.create", 201, "volume_id:id", json={"name": "v"}),
    ("DELETE", "/v1/volumes/{volume_id}"): exercised("volume.delete"),
    ("POST", "/v1/snapshots"): exercised(
        "snapshot.register", 201, "snapshot_id:id", json={"image": "alpine:3.20"}
    ),
    ("DELETE", "/v1/snapshots/{snapshot_id}"): exercised("snapshot.delete"),
    ("PUT", "/v1/org/quota"): exercised("quota.updated", json={"max_vcpus": 10}),
    ("POST", "/v1/webhooks"): exercised(
        "webhook.endpoint_created",
        201,
        "endpoint_id:id",
        json={"url": "https://hooks.example.com/in", "event_types": ["sandbox.started"]},
    ),
    ("PATCH", "/v1/webhooks/{endpoint_id}"): exercised(
        "webhook.endpoint_updated", json={"enabled": False}
    ),
    ("DELETE", "/v1/webhooks/{endpoint_id}"): exercised("webhook.endpoint_deleted"),
    ("POST", "/v1/api-keys"): exercised(
        "api_key.created", 201, "key_id:id", json={"name": "k", "scopes": ["sandboxes:read"]}
    ),
    ("DELETE", "/v1/api-keys/{key_id}"): exercised("api_key.revoked"),
    ("POST", "/v1/org/members"): exercised(
        "membership.added",
        201,
        "user_id:user_id",
        json={"email": "ada@example.com", "display_name": "Ada", "role": "viewer"},
    ),
    ("PATCH", "/v1/org/members/{user_id}"): exercised(
        "membership.role_changed", json={"role": "developer"}
    ),
    ("DELETE", "/v1/org/members/{user_id}"): exercised("membership.removed", 204),
    ("POST", SESSIONS + "/{session_id}/commands"): proven("toolbox.session.exec", SESSIONS_PROOF),
    ("POST", SESSIONS + "/{session_id}/commands/{command_id}/kill"): proven(
        "toolbox.session.kill", SESSIONS_PROOF
    ),
    ("POST", TB + "/code-contexts"): proven(
        "toolbox.code_contexts.create",
        "test_named_contexts_r35.py::test_a_named_create_is_audited_with_its_name",
    ),
    ("DELETE", TB + "/code-contexts/{context_id}"): proven(
        "toolbox.code_contexts.delete", CONTEXTS_PROOF
    ),
    ("POST", TB + "/code-contexts/{context_id}/interrupt"): proven(
        "toolbox.code_contexts.interrupt",
        "test_code_contexts_api.py::test_interrupt_is_audited",
    ),
    ("POST", TB + "/code-contexts/{context_id}/run"): proven(
        "toolbox.code_contexts.run", CONTEXTS_PROOF
    ),
    ("POST", TB + "/code-contexts/{context_id}/run/stream"): proven(
        "toolbox.code_contexts.run_stream",
        "test_code_context_stream_r34.py::test_the_stream_is_audited_with_the_details_of_a_run",
    ),
    ("POST", "/v1/snapshots/from-sandbox"): proven(
        "snapshot.create",
        "test_api_snapshot_resources.py::test_snapshot_create_audit_details_include_the_resources",
    ),
    ("POST", "/v1/images/builds"): proven(
        "image.build.request",
        "test_image_builds.py::test_two_identical_requests_build_once_and_reuse_the_ready_snapshot",
    ),
    ("POST", "/v1/volumes/{volume_id}/restore"): proven(
        "volume.restore",
        "test_volume_transfer_r67.py::test_restore_is_audited_with_the_name_and_the_bytes",
    ),
    ("POST", "/v1/webhooks/{endpoint_id}/deliveries/{delivery_id}/redeliver"): proven(
        "webhook.redelivered",
        "test_audit_outcome_r60.py::test_redeliver_writes_a_webhook_redelivered_event",
    ),
    ("POST", "/v1/auth/sso/exchange"): proven(
        "session.created",
        "test_sso.py::test_exchange_route_writes_a_session_created_audit_row",
    ),
    ("POST", "/v1/org/scim-tokens"): proven(
        "scim_token.created", "test_scim_tokens_api.py::test_minting_is_audited_without_the_token"
    ),
    ("DELETE", "/v1/org/scim-tokens/{token_id}"): proven(
        "scim_token.revoked",
        "test_scim_tokens_api.py::test_revoking_twice_is_idempotent_and_audits_once",
    ),
    ("POST", "/scim/v2/Users"): proven("user.created", SCIM_PROOF),
    ("PATCH", "/scim/v2/Users/{user_id}"): proven("membership.role_changed", SCIM_PROOF),
    ("DELETE", "/scim/v2/Users/{user_id}"): proven("membership.removed", SCIM_PROOF),
    ("PUT", "/scim/v2/Users/{user_id}"): proven(
        "membership.role_changed",
        "test_user_admin_scim.py::test_update_role_audits_and_keeps_the_external_id",
    ),
    ("POST", "/internal/egress/v1/policies"): exempt(
        "a MAC-authenticated read of the egress policy for the proxy; it changes no state"
    ),
}
WEBSOCKET_EXEMPT = {
    TB + "/pty/{pty_id}/connect": "attaches to a PTY that POST /pty created and audited "
    "(toolbox.pty.create); the attach changes no state and carries terminal data, never audited",
}
