# ADR-0006: Evidence-Based Findings and Independent Verification

- Status: Accepted (design baseline)
- Date: 2026-11-05

## Context

AI explanations and scanner alerts can be wrong. A crash may lack security relevance, and a patch may hide a symptom by disabling intended behavior. Continuous review and deep research need the same explicit evidence semantics.

The OpenAI inspiration separates research stages and runtime validation; the Vercel inspiration supplies a contextual change-review workflow. These are source-reported designs, not Sentra implementations. [S02](../research/SOURCES.md#s02), [S01](../research/SOURCES.md#s01)

## Alternatives

1. Treat model/scanner confidence as confirmation.
2. Require a weaponized exploit for every issue.
3. Use finding-class-specific validation, explicit uncertainty, and independent patch verification.

## Decision

Choose option 3. Separate candidate, validating, validated, rejected, and inconclusive states. Record validation basis as dynamic reproduction, static evidence review, or dependency advisory match. Severity, confidence, exploitability, disposition, and remediation remain separate fields.

Require a different verification task, reviewed oracle, and fresh isolated execution for patch verification. Check the original failure, patched behavior, normal operation, applicable regressions, and diff scope. Missing tests or skipped execution cannot pass. Static-only remediation without a suitable executable oracle remains a reviewed proposal, not a dynamically verified patch.

Do not infer fixed status from the absence of a finding in a later scan. A verified local patch and upstream application are different events. Preserve immutable input identities, raw/native evidence, artifact hashes, and audit history.

## Consequences

Some plausible findings and patches remain inconclusive. Verification costs time and resources, and multiple calls to the same model may share bias. Independent contexts and execution are mandatory; cross-provider/human review can improve assurance without proving perfect independence.

Minimal safe PoCs are preferred. Full exploitation is not required for every issue and requires a separate approved risk profile. CVSS may describe severity under assumptions; it cannot replace evidence. [S47](../research/SOURCES.md#s47)

## Validation and reversal

Phase 2 must exercise false positives, no-test success, stale revisions, disabled oracles, and functionality-breaking patches. Evaluate precision, reproduction, and patch outcomes with full denominators. New evidence methods require explicit criteria and a contract update; they cannot silently weaken existing verified-status semantics.
