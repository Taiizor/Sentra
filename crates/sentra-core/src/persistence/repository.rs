use super::{
    ApprovalIntent, AuditRecord, BudgetRecord, ConsumptionRecord, PersistenceError,
    PersistenceErrorKind as Kind, PersistentApprovalGrant, SessionRecord, SettlementStatus,
    SqliteConnectionManager, TransitionRecord,
    model::{self, MetadataDto, Snapshot, StoredApproval},
    transaction::ManagedTransaction,
};
use crate::{
    ApprovalId, Clock, CostUsd, EventId, Identifier, SecurityClassification, SessionId,
    SessionMetadata, SessionState,
};
use rusqlite::params;
use std::{fmt, sync::Arc};

fn error(kind: Kind) -> PersistenceError {
    PersistenceError::new(kind)
}
fn corrupt(_: PersistenceError) -> PersistenceError {
    error(Kind::Integrity)
}

/// Concrete initial repository. Raw SQL, connections and retry closures are private.
/// Only the separately retained authority can register contexts, issue/restore
/// receipts or reconcile final budget usage.
#[derive(Clone)]
pub struct PersistenceRepository {
    manager: SqliteConnectionManager,
    seal: Arc<()>,
}

/// Trusted local controller capability for the SAME persistent repository.
/// Never expose it to model/target/request handlers. It authenticates no human.
pub struct PersistentApprovalAuthority {
    repository: PersistenceRepository,
}
impl fmt::Debug for PersistenceRepository {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistenceRepository([redacted])")
    }
}
impl fmt::Debug for PersistentApprovalAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PersistentApprovalAuthority([privileged])")
    }
}

fn read_snapshot(
    tx: &mut ManagedTransaction<'_>,
    id: SessionId,
) -> Result<Option<(Snapshot, SessionRecord)>, PersistenceError> {
    let row = tx.optional("SELECT s.state,s.mode,s.classification_floor,s.context_generation,s.target_revision,s.created_at,x.project_root,x.operator_id,x.policy_id,x.snapshot_json FROM sessions s JOIN session_security_snapshots x ON s.session_id=x.session_id AND s.context_generation=x.context_generation WHERE s.session_id=?1",
        [id.to_string()], |row| Ok((row.get::<_, String>(0)?,row.get::<_, String>(1)?,row.get::<_, String>(2)?,row.get::<_, i64>(3)?,row.get::<_, String>(4)?,row.get::<_, String>(5)?,row.get::<_, String>(6)?,row.get::<_, String>(7)?,row.get::<_, String>(8)?,row.get::<_, String>(9)?)))?;
    let Some((state, mode, floor, generation, revision, created, root, operator, policy, json)) =
        row
    else {
        let exists: i64 = tx.query(
            "SELECT count(*) FROM sessions WHERE session_id=?1",
            [id.to_string()],
            |row| row.get(0),
        )?;
        if exists != 0 {
            return Err(error(Kind::Integrity));
        }
        return Ok(None);
    };
    let snapshot = Snapshot::from_json(&json).map_err(corrupt)?;
    let metadata = snapshot.validate().map_err(corrupt)?;
    if metadata.session_id != id
        || metadata.workspace_root != root
        || metadata.operator_id != operator
        || metadata.policy_digest != policy
        || metadata.operating_mode.as_str() != mode
        || model::time_text(metadata.created_at_utc)? != created
        || snapshot.classification_floor != floor
        || snapshot.generation != model::unsigned(generation).map_err(corrupt)?
        || snapshot.revision != revision
    {
        return Err(error(Kind::Integrity));
    }
    let record = SessionRecord {
        metadata,
        state: model::state(&state).map_err(corrupt)?,
        context_generation: snapshot.generation,
        target_revision: revision,
        classification_floor: model::class(&floor).map_err(corrupt)?,
        budget_limit: CostUsd::from_micro_usd(snapshot.budget_limit_micro_usd),
    };
    Ok(Some((snapshot, record)))
}

fn current(
    tx: &mut ManagedTransaction<'_>,
    intent: &ApprovalIntent<'_>,
) -> Result<Snapshot, PersistenceError> {
    crate::policy::engine::validate_operation_constraints(intent.classification, intent.action)
        .map_err(|_| error(Kind::PolicyDenied))?;
    let (snapshot, session) = read_snapshot(tx, intent.session.session_id)?
        .ok_or_else(|| error(Kind::ContextMismatch))?;
    if session.state.is_terminal() || intent.classification < session.classification_floor {
        return Err(error(Kind::PolicyDenied));
    }
    if !snapshot.matches(intent.session)?
        || snapshot.generation != intent.context_generation
        || snapshot.revision != intent.target_revision
    {
        return Err(error(Kind::ContextMismatch));
    }
    Ok(snapshot)
}

fn read_approval(
    tx: &mut ManagedTransaction<'_>,
    id: ApprovalId,
) -> Result<StoredApproval, PersistenceError> {
    let row = tx.optional("SELECT request_id,session_id,context_generation,target_revision,state,action_name,action_digest,classification,created_at,expires_at,issued_at,receipt_token FROM approval_requests WHERE request_id=?1", [id.to_string()], |r| Ok(StoredApproval {
        id:r.get(0)?,session:r.get(1)?,generation:r.get::<_, i64>(2)? as u64,revision:r.get(3)?,state:r.get(4)?,action_name:r.get(5)?,
        action_digest:r.get(6)?,classification:r.get(7)?,created:r.get(8)?,expires:r.get(9)?,issued:r.get(10)?,token:r.get(11)?,
    }))?.ok_or_else(|| error(Kind::InvalidApproval))?;
    model::parse_id(&row.id).map_err(corrupt)?;
    model::parse_id(&row.session).map_err(corrupt)?;
    model::integer(row.generation).map_err(corrupt)?;
    model::class(&row.classification).map_err(corrupt)?;
    let created = model::parse_time(&row.created).map_err(corrupt)?;
    let expires = model::parse_time(&row.expires).map_err(corrupt)?;
    if row.generation == 0
        || expires <= created
        || !model::valid_text(&row.revision)
        || !model::valid_text(&row.action_name)
        || row.action_digest.is_empty()
        || !matches!(
            row.state.as_str(),
            "PENDING" | "ISSUED" | "CONSUMED" | "REVOKED" | "EXPIRED"
        )
    {
        return Err(error(Kind::Integrity));
    }
    if let Some(issued) = &row.issued {
        model::parse_time(issued).map_err(corrupt)?;
    }
    if matches!(row.state.as_str(), "ISSUED" | "CONSUMED")
        && (row.issued.is_none() || row.token.is_none())
    {
        return Err(error(Kind::Integrity));
    }
    Ok(row)
}

fn binding_matches(
    row: &StoredApproval,
    snapshot: &Snapshot,
    intent: &ApprovalIntent<'_>,
) -> Result<(), PersistenceError> {
    if row.session != intent.session.session_id.to_string()
        || row.generation != snapshot.generation
        || row.revision != snapshot.revision
        || row.action_name != intent.action.action_name()
        || row.action_digest != intent.action.action_digest()
        || row.classification != intent.classification.as_str()
    {
        return Err(error(Kind::ContextMismatch));
    }
    Ok(())
}

fn validate_time(row: &StoredApproval, now: &str) -> Result<(), PersistenceError> {
    if now < row.created.as_str()
        || now >= row.expires.as_str()
        || row.issued.as_deref().is_some_and(|issued| now < issued)
    {
        return Err(error(Kind::ApprovalExpired));
    }
    Ok(())
}

fn audit(
    tx: &mut ManagedTransaction<'_>,
    session: SessionId,
    event: EventId,
    event_type: (&str, SecurityClassification),
    now: &str,
    action: Option<&str>,
    details: &serde_json::Value,
) -> Result<u64, PersistenceError> {
    let (kind, classification) = event_type;
    let sequence: i64 = tx.query(
        "SELECT COALESCE(MAX(sequence_number),0) FROM audit_events WHERE session_id=?1",
        [session.to_string()],
        |r| r.get(0),
    )?;
    let sequence = sequence.checked_add(1).ok_or_else(model::invalid)?;
    let (generation,revision,policy,actor): (i64,String,String,String)=tx.query("SELECT s.context_generation,s.target_revision,x.policy_id,x.operator_id FROM sessions s JOIN session_security_snapshots x ON s.session_id=x.session_id AND s.context_generation=x.context_generation WHERE s.session_id=?1",[session.to_string()],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)))?;
    let envelope = serde_json::json!({"version":1,"context_generation":generation,"target_revision":revision,"policy_id":policy,"operator_id":actor,"event":details});
    let json = serde_json::to_string(&envelope).map_err(|_| model::invalid())?;
    tx.execute("INSERT INTO audit_events(event_id,session_id,sequence_number,event_kind,classification,timestamp,action_digest,details_json) VALUES(?1,?2,?3,?4,?5,?6,?7,?8)",
        params![model::event_text(event)?,session.to_string(),sequence,kind,classification.as_str(),now,action,json])?;
    model::unsigned(sequence)
}

fn budget_used(
    tx: &mut ManagedTransaction<'_>,
    session: SessionId,
) -> Result<u64, PersistenceError> {
    let used: i64 = tx.query("SELECT COALESCE(SUM(COALESCE(actual_cost_micro_usd,reserved_cost_micro_usd)),0) FROM budget_reservations WHERE session_id=?1", [session.to_string()], |r| r.get(0))?;
    model::unsigned(used).map_err(corrupt)
}

impl PersistenceRepository {
    /// Bootstrap the storage adapter and separate privileged controller capability.
    /// Existing in-memory grants cannot be converted into persistent receipts.
    pub fn with_authority(manager: SqliteConnectionManager) -> (Self, PersistentApprovalAuthority) {
        let repository = Self {
            manager,
            seal: Arc::new(()),
        };
        let authority = PersistentApprovalAuthority {
            repository: repository.clone(),
        };
        (repository, authority)
    }

    /// Read a current persisted session using a short, serialized fresh transaction.
    pub fn session(&self, id: SessionId) -> Result<Option<SessionRecord>, PersistenceError> {
        self.manager
            .write(|tx| Ok(read_snapshot(tx, id)?.map(|(_, record)| record)))
    }

    /// Store a canonical pending request; this cannot issue or authorize a grant.
    pub fn request_approval(
        &self,
        id: ApprovalId,
        intent: &ApprovalIntent<'_>,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<ApprovalId, PersistenceError> {
        model::parse_id(&id.to_string())?;
        model::event_text(event)?;
        self.manager.write(|tx| {
            let snapshot = current(tx, intent)?;
            let now_time = clock.now(); let now = model::time_text(now_time)?;
            let expires = model::time_text(now_time.add_seconds(3600))?;
            if expires <= now { return Err(model::invalid()); }
            let digest = intent.action.action_digest();
            tx.execute("INSERT INTO approval_requests(request_id,session_id,context_generation,target_revision,state,action_name,action_digest,classification,display_summary,created_at,expires_at) VALUES(?1,?2,?3,?4,'PENDING',?5,?6,?7,?8,?9,?10)",
                params![id.to_string(), intent.session.session_id.to_string(), model::integer(snapshot.generation)?, snapshot.revision,
                    intent.action.action_name(), digest, intent.classification.as_str(), "Explicit controller approval required", now, expires])?;
            audit(tx, intent.session.session_id, event, ("ApprovalRequested", intent.classification), &now, Some(&digest), &serde_json::json!({"request_id":id.to_string()}))?;
            Ok(id)
        })
    }

    /// Compare every binding/provenance field, conditionally consume exactly one row,
    /// and commit its audit event in the SAME transaction. Returns only after COMMIT.
    pub fn consume_approval(
        &self,
        grant: &PersistentApprovalGrant,
        intent: &ApprovalIntent<'_>,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<ConsumptionRecord, PersistenceError> {
        if !Arc::ptr_eq(&self.seal, &grant.seal) {
            return Err(error(Kind::InvalidApproval));
        }
        self.manager.write(|tx| {
            let snapshot = current(tx, intent)?;
            if snapshot != grant.snapshot { return Err(error(Kind::ContextMismatch)); }
            let row = read_approval(tx, grant.request_id())?;
            binding_matches(&row, &snapshot, intent)?;
            let mut comparison = row.clone(); comparison.state = grant.approval.state.clone();
            if comparison != grant.approval { return Err(error(Kind::InvalidApproval)); }
            if row.state == "CONSUMED" { return Err(error(Kind::ApprovalReused)); }
            if row.state != "ISSUED" { return Err(error(Kind::InvalidApproval)); }
            let now = model::time_text(clock.now())?; validate_time(&row, &now)?;
            let changed = tx.execute("UPDATE approval_requests SET state='CONSUMED',consumed_at=?1,consumed_action_digest=?2 WHERE request_id=?3 AND session_id=?4 AND context_generation=?5 AND target_revision=?6 AND action_name=?7 AND action_digest=?2 AND classification=?8 AND state='ISSUED' AND created_at<=?1 AND issued_at<=?1 AND expires_at>?1 AND receipt_token=?9",
                params![now,row.action_digest,row.id,row.session,model::integer(row.generation)?,row.revision,row.action_name,row.classification,row.token])?;
            if changed != 1 { return Err(error(Kind::Conflict)); }
            let sequence = audit(tx, intent.session.session_id, event, ("ApprovalConsumed", intent.classification), &now, Some(&row.action_digest), &serde_json::json!({"request_id":row.id,"generation":row.generation}))?;
            Ok(ConsumptionRecord { request_id: grant.request_id(), audit_sequence: sequence })
        })
    }

    /// Persist a valid Core state transition with its event; terminal checkpoint
    /// failure is a separate post-commit outcome and never replays the transition.
    pub fn transition_session(
        &self,
        id: SessionId,
        from: SessionState,
        to: SessionState,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<TransitionRecord, PersistenceError> {
        let sequence = self.manager.write(|tx| {
            let (_, session) = read_snapshot(tx, id)?.ok_or_else(|| error(Kind::Conflict))?;
            if session.state != from || !from.can_transition_to(to) { return Err(error(Kind::Conflict)); }
            let now = model::time_text(clock.now())?;
            tx.execute("UPDATE sessions SET state=?1,updated_at=?2,completed_at=?3 WHERE session_id=?4 AND state=?5",
                params![to.as_str(),now,if to.is_terminal() {Some(&now)} else {None},id.to_string(),from.as_str()])?;
            audit(tx, id, event, ("SessionTransition", session.classification_floor), &now, None, &serde_json::json!({"from":from.as_str(),"to":to.as_str()}))
        })?;
        Ok(TransitionRecord {
            audit_sequence: sequence,
            checkpoint: to.is_terminal().then(|| self.manager.checkpoint(false)),
        })
    }

    /// Bounded explicit audit read; no automatic diagnostic/export of private fields.
    pub fn audit_events(
        &self,
        id: SessionId,
        after: u64,
        limit: usize,
    ) -> Result<Vec<AuditRecord>, PersistenceError> {
        if !(1..=1000).contains(&limit) {
            return Err(model::invalid());
        }
        self.manager.write(|tx| {
            let rows = tx.collect("SELECT event_id,sequence_number,event_kind,classification,timestamp,action_digest,details_json FROM audit_events WHERE session_id=?1 AND sequence_number>?2 ORDER BY sequence_number LIMIT ?3",
                params![id.to_string(),model::integer(after)?,limit as i64], |r| Ok((r.get::<_,String>(0)?,r.get::<_,i64>(1)?,r.get::<_,String>(2)?,r.get::<_,String>(3)?,r.get::<_,String>(4)?,r.get::<_,Option<String>>(5)?,r.get::<_,String>(6)?)))?;
            rows.into_iter().map(|(event,sequence,kind,class,time,digest,json)| {
                serde_json::from_str::<serde_json::Value>(&json).map_err(|_| error(Kind::Integrity))?;
                Ok(AuditRecord { event_id: EventId::from_bytes(*model::parse_id(&event).map_err(corrupt)?.as_bytes()),session_id:id,
                    sequence_number:model::unsigned(sequence).map_err(corrupt)?,event_kind:kind,classification:model::class(&class).map_err(corrupt)?,
                    timestamp:model::parse_time(&time).map_err(corrupt)?,action_digest:digest,details_json:json })
            }).collect()
        })
    }

    /// Atomically reserve against the trusted persisted total budget, including all
    /// uncertain/cancelled usage. No real model price or usage is inferred.
    pub fn reserve_budget(
        &self,
        id: Identifier,
        session: SessionId,
        model: &str,
        amount: CostUsd,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<BudgetRecord, PersistenceError> {
        model::parse_id(&id.to_string())?;
        let amount_int = model::integer(amount.as_micro_usd())?;
        if !model::valid_text(model) {
            return Err(model::invalid());
        }
        self.manager.write(|tx| {
            let (snapshot, record) = read_snapshot(tx, session)?.ok_or_else(|| error(Kind::Conflict))?;
            if record.state.is_terminal() { return Err(error(Kind::PolicyDenied)); }
            if budget_used(tx, session)?.checked_add(amount.as_micro_usd()).is_none_or(|total| total > snapshot.budget_limit_micro_usd) { return Err(error(Kind::BudgetExceeded)); }
            let now = model::time_text(clock.now())?;
            tx.execute("INSERT INTO budget_reservations(reservation_id,session_id,model_id,reserved_cost_micro_usd,state,reserved_at) VALUES(?1,?2,?3,?4,'RESERVED',?5)", params![id.to_string(),session.to_string(),model,amount_int,now])?;
            audit(tx, session, event, ("BudgetReserved", record.classification_floor), &now, None, &serde_json::json!({"reservation_id":id.to_string(),"micro_usd":amount.as_micro_usd()}))?;
            Ok(BudgetRecord { reservation_id:id,reserved:amount,actual:None,state:"RESERVED".into() })
        })
    }

    /// Total committed final spend plus unresolved upper bounds.
    pub fn budget_used(&self, session: SessionId) -> Result<CostUsd, PersistenceError> {
        self.manager
            .write(|tx| budget_used(tx, session).map(CostUsd::from_micro_usd))
    }
}

impl PersistentApprovalAuthority {
    /// Register a new session or replace its trusted security context, incrementing
    /// generation atomically. IDs are provided by the trusted caller; collisions deny.
    pub fn register_session(
        &self,
        metadata: &SessionMetadata,
        revision: &str,
        floor: SecurityClassification,
        budget_limit: CostUsd,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<SessionRecord, PersistenceError> {
        let dto = MetadataDto::from_domain(metadata)?;
        model::integer(budget_limit.as_micro_usd())?;
        if !model::valid_text(revision) {
            return Err(model::invalid());
        }
        self.repository.manager.write(|tx| {
            let old = read_snapshot(tx, metadata.session_id)?;
            let generation = if let Some((snapshot, record)) = &old {
                if record.state.is_terminal() || record.metadata.created_at_utc != metadata.created_at_utc { return Err(error(Kind::ContextMismatch)); }
                if budget_used(tx, metadata.session_id)? > budget_limit.as_micro_usd() { return Err(error(Kind::BudgetExceeded)); }
                snapshot.generation.checked_add(1).ok_or_else(model::invalid)?
            } else { 1 };
            let snapshot = Snapshot {version:1, metadata:dto.clone(),generation,revision:revision.into(),classification_floor:floor.as_str().into(),budget_limit_micro_usd:budget_limit.as_micro_usd()};
            let json = snapshot.json()?;
            let now_time = clock.now(); if now_time < metadata.created_at_utc { return Err(model::invalid()); }
            let now = model::time_text(now_time)?;
            if old.is_none() {
                tx.execute("INSERT INTO sessions(session_id,state,mode,classification_floor,context_generation,target_revision,created_at,updated_at,completeness) VALUES(?1,'CREATED',?2,?3,?4,?5,?6,?7,?8)",
                    params![metadata.session_id.to_string(),metadata.operating_mode.as_str(),floor.as_str(),model::integer(generation)?,revision,model::time_text(metadata.created_at_utc)?,now,metadata.completeness.as_str()])?;
            } else {
                tx.execute("UPDATE sessions SET mode=?1,classification_floor=?2,context_generation=?3,target_revision=?4,updated_at=?5,completeness=?6 WHERE session_id=?7",
                    params![metadata.operating_mode.as_str(),floor.as_str(),model::integer(generation)?,revision,now,metadata.completeness.as_str(),metadata.session_id.to_string()])?;
            }
            tx.execute("INSERT INTO session_security_snapshots(session_id,context_generation,project_root,operator_id,policy_id,registered_at,snapshot_json) VALUES(?1,?2,?3,?4,?5,?6,?7)",
                params![metadata.session_id.to_string(),model::integer(generation)?,metadata.workspace_root,metadata.operator_id,metadata.policy_digest,now,json])?;
            audit(tx, metadata.session_id, event, (if old.is_none() {"SessionCreated"} else {"SecurityContextRegistered"}, floor), &now, None, &serde_json::json!({"generation":generation}))?;
            Ok(SessionRecord {metadata:metadata.clone(),state:old.map_or(SessionState::Created,|(_,record)|record.state),context_generation:generation,target_revision:revision.into(),classification_floor:floor,budget_limit})
        })
    }

    /// Issue only a PENDING current request. This private receipt is returned only
    /// after ISSUED state and its audit event commit together.
    pub fn issue_grant(
        &self,
        id: ApprovalId,
        intent: &ApprovalIntent<'_>,
        actor: &str,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<PersistentApprovalGrant, PersistenceError> {
        if !model::valid_text(actor) {
            return Err(model::invalid());
        }
        self.repository.manager.write(|tx| {
            let snapshot = current(tx, intent)?; let mut row = read_approval(tx,id)?;
            binding_matches(&row,&snapshot,intent)?;
            if row.state != "PENDING" { return Err(error(Kind::InvalidApproval)); }
            let now = model::time_text(clock.now())?; validate_time(&row,&now)?;
            let token = format!("local-correlation:{}:{}",row.id,row.generation);
            let changed = tx.execute("UPDATE approval_requests SET state='ISSUED',issued_at=?1,receipt_token=?2 WHERE request_id=?3 AND state='PENDING'",params![now,token,row.id])?;
            if changed != 1 { return Err(error(Kind::Conflict)); }
            audit(tx,intent.session.session_id,event,("ApprovalIssued",intent.classification),&now,Some(&row.action_digest),&serde_json::json!({"request_id":row.id,"actor":actor}))?;
            row.state="ISSUED".into(); row.issued=Some(now); row.token=Some(token);
            Ok(PersistentApprovalGrant {seal:Arc::clone(&self.repository.seal),snapshot,approval:row})
        })
    }

    /// Explicit trusted recovery after reopen; no consumer can restore a receipt
    /// from a request ID or serialized DTO. Human identity is not authenticated here.
    pub fn recover_issued_grant(
        &self,
        id: ApprovalId,
        intent: &ApprovalIntent<'_>,
        actor: &str,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<PersistentApprovalGrant, PersistenceError> {
        if !model::valid_text(actor) {
            return Err(model::invalid());
        }
        self.repository.manager.write(|tx| {
            let snapshot = current(tx, intent)?;
            let row = read_approval(tx, id)?;
            binding_matches(&row, &snapshot, intent)?;
            if row.state == "CONSUMED" {
                return Err(error(Kind::ApprovalReused));
            }
            if row.state != "ISSUED" {
                return Err(error(Kind::InvalidApproval));
            }
            let now = model::time_text(clock.now())?;
            validate_time(&row, &now)?;
            audit(
                tx,
                intent.session.session_id,
                event,
                ("ApprovalReceiptRecovered", intent.classification),
                &now,
                Some(&row.action_digest),
                &serde_json::json!({"request_id":row.id,"actor":actor}),
            )?;
            Ok(PersistentApprovalGrant {
                seal: Arc::clone(&self.repository.seal),
                snapshot,
                approval: row,
            })
        })
    }

    /// Revoke an unconsumed record and its audit event atomically.
    pub fn revoke_grant(
        &self,
        id: ApprovalId,
        actor: &str,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<(), PersistenceError> {
        if !model::valid_text(actor) {
            return Err(model::invalid());
        }
        self.repository.manager.write(|tx| {
            let row=read_approval(tx,id)?;
            if !matches!(row.state.as_str(),"PENDING"|"ISSUED") { return Err(error(Kind::InvalidApproval)); }
            let session=SessionId::from_bytes(*model::parse_id(&row.session)?.as_bytes());
            let (_,record)=read_snapshot(tx,session)?.ok_or_else(||error(Kind::Conflict))?;
            let now=model::time_text(clock.now())?;
            tx.execute("UPDATE approval_requests SET state='REVOKED',revoked_at=?1,revocation_reason='Trusted controller revocation' WHERE request_id=?2",params![now,row.id])?;
            audit(tx,session,event,("ApprovalRevoked",record.classification_floor.max(model::class(&row.classification)?)),&now,None,&serde_json::json!({"request_id":row.id,"actor":actor}))?;
            Ok(())
        })
    }

    /// Reconcile final budget usage via explicit settlement status.
    /// Unconfirmed cancellation or uncertain partial usage never releases
    /// an upper bound; confirmed cancellation without usage also remains unknown.
    pub fn settle_budget(
        &self,
        id: Identifier,
        status: SettlementStatus,
        event: EventId,
        clock: &impl Clock,
    ) -> Result<BudgetRecord, PersistenceError> {
        if let Some(actual) = status.actual_cost() {
            model::integer(actual.as_micro_usd())?;
        }
        self.repository.manager.write(|tx| {
            let (session, reserved, old_actual, old_state): (String, i64, Option<i64>, String) = tx
                .optional(
                    "SELECT session_id,reserved_cost_micro_usd,actual_cost_micro_usd,state FROM budget_reservations WHERE reservation_id=?1",
                    [id.to_string()],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )?
                .ok_or_else(|| error(Kind::Conflict))?;
            if old_actual.is_some() {
                return Err(error(Kind::Conflict));
            }
            let session =
                SessionId::from_bytes(*model::parse_id(&session).map_err(corrupt)?.as_bytes());
            let (_, record) =
                read_snapshot(tx, session)?.ok_or_else(|| error(Kind::Conflict))?;
            let reserved = model::unsigned(reserved).map_err(corrupt)?;
            let final_actual = status.actual_cost();
            if final_actual.is_some_and(|cost| cost.as_micro_usd() > reserved) {
                return Err(model::invalid());
            }
            let new_state = match status {
                SettlementStatus::Completed(_) => "SETTLED",
                SettlementStatus::CancelledWithUsage(_) | SettlementStatus::CancelledUncertain => {
                    "CANCELLED"
                }
                SettlementStatus::UncertainPartial => old_state.as_str(),
            };
            let now = model::time_text(clock.now())?;
            let final_int = final_actual
                .map(|cost| model::integer(cost.as_micro_usd()))
                .transpose()?;
            let settled_time = match status {
                SettlementStatus::Completed(_) | SettlementStatus::CancelledWithUsage(_) => {
                    Some(&now)
                }
                SettlementStatus::CancelledUncertain | SettlementStatus::UncertainPartial => None,
            };
            tx.execute(
                "UPDATE budget_reservations SET state=?1,actual_cost_micro_usd=?2,settled_at=?3 WHERE reservation_id=?4 AND actual_cost_micro_usd IS NULL",
                params![new_state, final_int, settled_time, id.to_string()],
            )?;
            let event_name = match status {
                SettlementStatus::Completed(_) | SettlementStatus::CancelledWithUsage(_) => {
                    "BudgetSettled"
                }
                SettlementStatus::CancelledUncertain | SettlementStatus::UncertainPartial => {
                    "BudgetUsageUnknown"
                }
            };
            let status_str = match status {
                SettlementStatus::Completed(_) => "COMPLETED",
                SettlementStatus::CancelledWithUsage(_) => "CANCELLED_WITH_USAGE",
                SettlementStatus::CancelledUncertain => "CANCELLED_UNCERTAIN",
                SettlementStatus::UncertainPartial => "UNCERTAIN_PARTIAL",
            };
            let details = serde_json::json!({
                "reservation_id": id.to_string(),
                "status": status_str,
                "final_usage_known": final_actual.is_some(),
            });
            audit(
                tx,
                session,
                event,
                (event_name, record.classification_floor),
                &now,
                None,
                &details,
            )?;
            Ok(BudgetRecord {
                reservation_id: id,
                reserved: CostUsd::from_micro_usd(reserved),
                actual: final_actual,
                state: new_state.into(),
            })
        })
    }
}
