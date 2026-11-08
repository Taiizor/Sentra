CREATE TABLE tasks (
    task_id TEXT PRIMARY KEY NOT NULL CHECK(length(task_id) = 36),
    session_id TEXT NOT NULL,
    sequence_number INTEGER NOT NULL CHECK(sequence_number > 0),
    title TEXT NOT NULL,
    state TEXT NOT NULL CHECK(state IN ('PENDING','IN_PROGRESS','COMPLETED','FAILED','CANCELLED','BLOCKED')),
    created_at TEXT NOT NULL CHECK(length(created_at) = 24),
    updated_at TEXT NOT NULL CHECK(length(updated_at) = 24),
    completed_at TEXT,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    UNIQUE(session_id, sequence_number)
);
CREATE INDEX idx_tasks_session ON tasks(session_id, sequence_number);
CREATE INDEX idx_tasks_state ON tasks(state);

CREATE TABLE manifests (
    manifest_id TEXT PRIMARY KEY NOT NULL CHECK(length(manifest_id) = 36),
    session_id TEXT NOT NULL,
    manifest_kind TEXT NOT NULL CHECK(manifest_kind IN ('SOURCE_SNAPSHOT','OPERATION','DISCOVERY')),
    content_digest TEXT NOT NULL CHECK(length(content_digest) > 0),
    created_at TEXT NOT NULL CHECK(length(created_at) = 24),
    canonical_json TEXT NOT NULL CHECK(json_valid(canonical_json)),
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE
);
CREATE INDEX idx_manifests_session ON manifests(session_id);
CREATE INDEX idx_manifests_digest ON manifests(content_digest);

CREATE TABLE attempts (
    attempt_id TEXT PRIMARY KEY NOT NULL CHECK(length(attempt_id) = 36),
    task_id TEXT NOT NULL,
    session_id TEXT NOT NULL,
    attempt_number INTEGER NOT NULL CHECK(attempt_number > 0),
    state TEXT NOT NULL CHECK(state IN ('RECORDED','PREPARED','RELEASE_RECORDED','RUNNING_CONFIRMED','RESULT_RECORDED','UNCERTAIN','NOT_STARTED_CONFIRMED')),
    fencing_epoch INTEGER NOT NULL CHECK(fencing_epoch > 0),
    execution_id TEXT NOT NULL CHECK(length(execution_id) = 36),
    action_name TEXT NOT NULL,
    action_digest TEXT NOT NULL,
    reservation_id TEXT,
    request_id TEXT,
    manifest_id TEXT,
    created_at TEXT NOT NULL CHECK(length(created_at) = 24),
    prepared_at TEXT,
    released_at TEXT,
    terminal_outcome TEXT CHECK(terminal_outcome IS NULL OR terminal_outcome IN ('COMPLETED','FAILED','CANCELLED','TIMED_OUT')),
    terminal_details_json TEXT CHECK(terminal_details_json IS NULL OR json_valid(terminal_details_json)),
    settled_at TEXT,
    FOREIGN KEY(task_id) REFERENCES tasks(task_id) ON DELETE CASCADE,
    FOREIGN KEY(session_id) REFERENCES sessions(session_id) ON DELETE CASCADE,
    FOREIGN KEY(reservation_id) REFERENCES budget_reservations(reservation_id),
    FOREIGN KEY(request_id) REFERENCES approval_requests(request_id),
    FOREIGN KEY(manifest_id) REFERENCES manifests(manifest_id),
    UNIQUE(task_id, attempt_number),
    UNIQUE(execution_id),
    CHECK(state != 'PREPARED' OR (prepared_at IS NOT NULL)),
    CHECK(state != 'RELEASE_RECORDED' OR (released_at IS NOT NULL)),
    CHECK(state != 'RESULT_RECORDED' OR (terminal_outcome IS NOT NULL AND settled_at IS NOT NULL))
);
CREATE INDEX idx_attempts_task ON attempts(task_id, attempt_number);
CREATE INDEX idx_attempts_session_state ON attempts(session_id, state);
CREATE INDEX idx_attempts_execution ON attempts(execution_id);
