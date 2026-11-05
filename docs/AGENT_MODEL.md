# Agent Responsibilities and Communication

Sentra agents are scoped reasoning tasks under a deterministic orchestrator. A role is a capability boundary, not a claim that several separate model providers are required. The product can schedule role tasks sequentially before it supports parallel execution.

## Role contract

| Role | Input | Allowed proposals / tools | Cannot do |
| --- | --- | --- | --- |
| Scout | Scoped source/context and project threat model | Read approved context; propose ranked audit targets and coverage gaps | Run target code, confirm findings, allocate peers, or broaden scope |
| Analyst | Audit target/diff, context, existing protections | Form hypotheses, retrieve scoped context, request tool/reproduction tasks | Treat model confidence as evidence or approve execution |
| Validator | Hypothesis and immutable source | Propose minimal PoC/harness, request approved sandbox runs, minimize inputs | Grant validated status or edit the evidence of earlier runs |
| Impact assessor | Admitted validation evidence and attacker model | Propose bounded impact checks and severity rationale | Infer privilege escalation from a crash or execute high-risk tests without approval |
| Patch author | Validated root cause, source snapshot, constraints | Produce an overlay diff and proposed regression cases | Modify operator checkout, approve its own patch, or alter verifier results |
| Independent verifier | Source, hypothesis, evidence references, patch, expected behavior | Review or design the oracle, run clean original/patched checks, recommend evidence disposition | Reuse an author-controlled environment or silently waive required checks |
| Reporter | Admitted structured records and accessible artifacts | Produce local summaries, limitations, and redacted export proposals | Invent missing evidence, change severity state, or publish externally |

The orchestrator owns scheduling, capability checks, leases, retry limits, budget reservations, and cancellation. The policy service owns permissions. The evidence service performs state transitions after required structured decisions and artifact checks. No agent can directly edit those stores or issue approval credentials.

Provider, Git, execution, and scanner adapters are service boundaries; they are not privileged conversational agents. A future integration agent can propose a comment or PR, but the integration broker still enforces approval and exact revision binding.

## Context and trust

Trusted control instructions come from the installed Sentra policy and the operator's recorded scope. Target source, comments, AGENTS.md files, issue text, dependency metadata, web content, logs, model output, and third-party adapter results are untrusted context. They may describe an instruction but cannot grant capabilities or change system policy.

Attach origin and classification labels to context segments. Retrieve by approved artifact ID and bounded ranges, not arbitrary paths/URLs emitted by a model. Keep target content out of trusted instruction fields. Escaping or prompt wording alone is not a security boundary; the broker enforces all permissions independently of the conversation.

Do not persist private chain-of-thought as required audit evidence. Persist task inputs, selected context references, concise structured rationale, tool requests/results, provider request metadata, and observable decisions. Retention/redaction policies apply to any raw prompts/responses retained for debugging.

## Task and message envelope

The following is a design contract, not an implemented schema.

| Field | Meaning |
| --- | --- |
| schema_version / message_type | Negotiated major/minor contract and explicit request/result/event kind |
| message_id / correlation_id | Unique message and request linkage |
| session_id / task_id / parent_task_id | Campaign and causal lineage |
| role / actor_id / issuer | Assigned role, accountable actor, and authenticating service |
| input_refs / source_digest | Immutable source and evidence references |
| context_refs / classification | Scoped retrieval and sensitivity labels |
| requested_capabilities / policy_digest | What the task needs and which policy governs it |
| approval_ref / lease_id / expires_at | Current authority and bounded execution lifetime |
| idempotency_key / attempt | Deduplication and retry lineage |
| budgets / deadline | Token, currency reservation, task, wall-time, and worker limits |
| hypothesis / expected_observation | Falsifiable claim and success/failure oracle |
| result_refs / limitations / status | Bounded result artifacts and explicit incomplete outcome |

Workers/model adapters cannot choose their own actor identity, role, approval, or lease. The core derives these from authenticated dispatch state. Reject unknown required fields/versions, mismatched source digests, forged issuer fields, stale leases, oversized messages, and result references outside the task's artifact namespace.

## Communication rules

1. The core emits a scoped task with immutable references and reserved resources.
2. The agent proposes typed capability calls. The broker validates arguments, scope, classification, lease, approval, and budgets.
3. Approved calls return result references and bounded structured metadata. Raw logs are sanitized and remain untrusted.
4. The agent returns a structured claim/result with rationale and limitations.
5. The evidence service admits artifacts and schedules the next independent role if the task outcome permits it.

Agents communicate through these durable messages, not shared mutable memory or direct peer shell channels. Sibling tasks can consume an approved shared evidence reference but cannot overwrite one another's artifacts. A task asking for another agent is a proposal to the scheduler, not permission to spawn arbitrary processes.

## Independence requirements

Finding validation must separate the candidate author from the final evidence review. A Validator may create a PoC, but the verifier checks that it exercises the claimed boundary on the intended revision, rather than merely crashing arbitrary code.

Patch verification uses a different task and fresh VM/overlay, with no inherited author execution state. The verifier can see the diff and stated root cause but must evaluate expected behavior and test oracle independently. The patch author can suggest tests; the verifier decides whether they are meaningful. Record whether provider/model/context overlap remains, because separate calls can share systematic errors.

The verifier checks the unpatched baseline, patched target, expected normal behavior, relevant regression tests, and unchanged harness/oracle integrity. Missing tests, disabled assertions, altered expected outputs, blanket exception handling, or removed functionality require explicit review and can make the result inconclusive or failed.

## Budget and failure behavior

Reserve maximum permitted model cost before dispatch and reconcile against actual usage. If usage is unavailable or endpoint behavior is incompatible, stop or use a declared conservative reservation; do not assume zero cost. Enforce separate worker and model quotas. A model cannot authorize another paid request by promising future value.

Bound retries by failure type: retry transient transport failures with idempotency; do not retry invalid permissions, stale revisions, schema failures, or ambiguous sensitive side effects automatically. On cancellation revoke pending work, request worker termination, and record unresolved remote execution explicitly.

Parallelism, model choice, and final research defaults are validation questions. This Phase 0 documentation was prepared without delegating work to sub-agents.
