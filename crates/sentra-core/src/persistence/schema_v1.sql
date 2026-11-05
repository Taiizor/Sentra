CREATE TABLE schema_migrations (
    version INTEGER PRIMARY KEY CHECK(version > 0),
    description TEXT NOT NULL,
    applied_at TEXT NOT NULL CHECK(length(applied_at) = 24),
    checksum TEXT NOT NULL
);
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY NOT NULL CHECK(length(session_id) = 36),
    state TEXT NOT NULL CHECK(state IN ('CREATED','SCOPED','PLANNED','RUNNING','WAITING_FOR_APPROVAL','PAUSED','COMPLETED','FAILED','CANCELLED')),
    mode TEXT NOT NULL CHECK(mode IN ('CONTINUOUS_REVIEW','DEEP_SECURITY_RESEARCH')),
    classification_floor TEXT NOT NULL CHECK(classification_floor IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
    context_generation INTEGER NOT NULL DEFAULT 1 CHECK(context_generation > 0),
    target_revision TEXT NOT NULL CHECK(length(target_revision) > 0),
    created_at TEXT NOT NULL CHECK(length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK(length(updated_at) = 24),
    completed_at TEXT,
    completeness TEXT CHECK(completeness IN ('COMPLETE','PARTIAL','UNSUPPORTED')),
    failure_reason TEXT
);
CREATE INDEX idx_sessions_state ON sessions(state);
CREATE INDEX idx_sessions_created_at ON sessions(created_at);
CREATE TABLE session_security_snapshots (
    session_id TEXT NOT NULL,
    context_generation INTEGER NOT NULL CHECK(context_generation > 0),
    project_root TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    policy_id TEXT NOT NULL,
    registered_at TEXT NOT NULL CHECK(length(registered_at) = 24),
    snapshot_json TEXT NOT NULL CHECK(json_valid(snapshot_json)),
    PRIMARY KEY(session_id, context_generation),
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
CREATE TABLE audit_events (
    event_id TEXT PRIMARY KEY NOT NULL CHECK(length(event_id) = 36),
    session_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL CHECK(sequence_number > 0),
    event_kind TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
    timestamp TEXT NOT NULL CHECK(length(timestamp) = 24),
    action_digest TEXT,
    details_json TEXT NOT NULL CHECK(json_valid(details_json)),
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE(session_id, sequence_number)
);
CREATE INDEX idx_audit_session_seq ON audit_events(session_id, sequence_number);
CREATE INDEX idx_audit_timestamp ON audit_events(timestamp);
CREATE TABLE approval_requests (
    request_id TEXT PRIMARY KEY NOT NULL CHECK(length(request_id) = 36),
    session_id TEXT NOT NULL,
    context_generation INTEGER NOT NULL CHECK(context_generation > 0),
    target_revision TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PENDING','ISSUED','CONSUMED','REVOKED','EXPIRED')),
    action_name TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    classification TEXT NOT NULL CHECK(classification IN ('PUBLIC','INTERNAL','CONFIDENTIAL','RESTRICTED')),
    display_summary TEXT NOT NULL,
    created_at TEXT NOT NULL CHECK(length(created_at) = 24),
    expires_at TEXT NOT NULL CHECK(length(expires_at) = 24),
    issued_at TEXT,
    consumed_at TEXT,
    consumed_action_digest TEXT,
    receipt_token TEXT,
    revoked_at TEXT,
    revocation_reason TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY(session_id, context_generation) REFERENCES session_security_snapshots(session_id, context_generation),
    CHECK(expires_at > created_at),
    CHECK(state = 'PENDING' OR (issued_at IS NOT NULL AND receipt_token IS NOT NULL) OR state IN ('REVOKED','EXPIRED')),
    CHECK(state != 'CONSUMED' OR (consumed_at IS NOT NULL AND consumed_action_digest IS NOT NULL AND consumed_action_digest = action_digest))
);
CREATE INDEX idx_approvals_session ON approval_requests(session_id);
CREATE INDEX idx_approvals_state ON approval_requests(state);
CREATE INDEX idx_approvals_lookup ON approval_requests(session_id, state, expires_at);
CREATE TABLE budget_reservations (
    reservation_id TEXT PRIMARY KEY NOT NULL CHECK(length(reservation_id) = 36),
    session_id TEXT NOT NULL,
    model_id TEXT NOT NULL,
    reserved_cost_micro_usd INTEGER NOT NULL CHECK(reserved_cost_micro_usd >= 0),
    actual_cost_micro_usd INTEGER CHECK(actual_cost_micro_usd >= 0 AND actual_cost_micro_usd <= reserved_cost_micro_usd),
    state TEXT NOT NULL CHECK(state IN ('RESERVED','SETTLED','CANCELLED','EXPIRED')),
    reserved_at TEXT NOT NULL CHECK(length(reserved_at) = 24),
    settled_at TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    CHECK(state != 'SETTLED' OR (actual_cost_micro_usd IS NOT NULL AND settled_at IS NOT NULL))
);
CREATE INDEX idx_budget_session ON budget_reservations(session_id);
