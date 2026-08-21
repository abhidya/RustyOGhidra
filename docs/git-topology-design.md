# Git topology redesign — lineage separation for port artifacts (v1)

Status: design for adversarial review. No code in this document has been
implemented; every "current code" claim below was re-verified in-repo on
2026-08-21 with file:line citations. **Caveat on line numbers:** a separate
audit was landing bare-push fixes in `src/port_wasm_units.py` concurrently
with this document's survey (e.g. `_push_product` did not exist at the start
of the survey and did at the end), so citations into that file give the
function name first and the line range as of the final read; the function
names are the stable reference.

The owner directive (binding, restated):

> Port artifacts — staging trees, ledgers, status/state JSON, registries,
> oracle evidence — must NEVER appear on GotYaForce `main`. `main` is
> engineering + product code + certified final-build content only.

And the standing goals it must be reconciled with (compile-fix-loop-design.md
§0): **G3 — git pushes are the heartbeat; absence must mean breakage,
detectably.** Today the heartbeat is implemented by pushing artifact commits
to `origin/main` (AGENTS.md monitoring invariant: "`main` should receive a
push whenever a unit goes green"). Those two requirements now conflict; the
cure is lineage separation: the heartbeat moves to a dedicated artifact
lineage, and `main` receives artifacts only through one explicit, certified
promotion path.

## 0. Requirements (the only source of design decisions)

R1. Artifacts never on GotYaForce `main` — not in its tree, and (owner's
    choice of migration option, §6) possibly not in its history either.
R2. G3 preserved: per-unit pushes keep flowing somewhere the owner can watch
    remotely; push-failure carry-forward keeps today's semantics exactly.
R3. Every push in driver and journal code carries an explicit
    `<remote> <refspec>` — no push may depend on ambient upstream config.
    (The contamination incident rode exactly that: a bare `git push` in the
    assembly-gate ledger hook landed one `port-assembly:` commit on
    `origin/main` per green — recorded in the surviving comment at
    `src/port_wasm_units.py:1873-1885`.)
R4. One and only one writer may move artifacts to `main`, and it is
    explicit and gated (§4).
R5. The driver tool (OGhidra repo) and the artifact store (GotYaForce repo)
    are different repos with different remotes and different rules; the
    design must be precise about which repo each mechanism lives in (§2.1).

## 1. Current code reality (verified 2026-08-21)

### 1.1 Two repos, two roles

- **OGhidra** (`research/tools/OGhidra`, a nested git repo inside the
  GotYaForce checkout): the driver TOOL. `origin` is LLNL upstream — never
  pushed; the user's fork is remote `fork`, and `main`'s upstream is
  `fork/main` (AGENTS.md "Git traps"). Driver-code commits are engineering
  and land here on review-pass.
- **GotYaForce** (`D:\GotYaForce`, remote `origin` =
  `github.com/abhidya/GotYaForce.git`): product repo AND, today, the
  artifact store. The driver resolves it as `repo_root`
  (`WasmUnitDriver.__init__`, `src/port_wasm_units.py:1218-1226`) and runs
  every artifact git operation there (`_git`, cwd=`repo_root`,
  `src/port_wasm_units.py:1941-1948`).

### 1.2 Every driver git write, enumerated

All of the following run in the GotYaForce **main worktree**, i.e. commit
onto whatever branch is checked out there — in practice `main`:

1. **Unit staging/green commits** — `_commit_unit`
   (`src/port_wasm_units.py:1950-1986`): pathspec'd add+commit of
   `research/decomp/port-units-staging/<name>` (compile-only staging) or
   `research/decomp/port-units/<name>` (oracle green), message
   `port-staging: <name> wasm unit LINKED (unoracled, not for integration)`
   or `port: <name> wasm unit green (oracle <summary>)`, then a product push.
   `extra_paths` ride the same commit — that is the **T2c registry
   co-commit**: a harvest that changed
   `research/decomp/generated/finish-game-port/knowledge-registry.json`
   passes `registry_rel` into the unit's own commit
   (`src/port_wasm_units.py:2569-2643`), one push, G3-preserving.
2. **The product push** — `_push_product`
   (`src/port_wasm_units.py:1988-2000`, added by the concurrent bare-push
   audit): `git push origin HEAD` with one retry. Its docstring states the
   current contract explicitly: greens land on GotYaForce `main` per the
   runbook invariant. Under this design that contract is superseded (§3).
3. **T2b assembly-gate ledger commits** — `_maybe_run_assembly_gate`
   (`src/port_wasm_units.py:1834-1908`): after every green, on MATERIAL
   ledger change only, a local pathspec'd commit of
   `research/decomp/data/assembly-gate.json`, message `port-assembly: gate
   N=<n> pass|FAIL ...`, **no push** — it rides the next sanctioned push.
   The comment at 1873-1885 records that a bare push here was the
   `origin/main` contamination vector.
4. **T3 promotion commits** — `_reverify_unit_inner`
   (`src/port_wasm_units.py:3292-3532`) via `_commit_paths`
   (`src/port_wasm_units.py:3267-3290`, pushes through `_push_product`):
   on oracle pass, copy staging → `research/decomp/port-units/<name>`,
   commit `port: <name> wasm unit promoted (oracle <summary>)` (with
   registry promotion co-commit), journal, then a separate deletion commit
   `port: remove staged copy of promoted unit <name>`
   (`_remove_staged_copy`, `src/port_wasm_units.py:3534-3556`). On oracle
   red, a registry revocation commit `port-registry: revoke <name> entries`
   (3359-3363).
5. **d5-migrate registry revocations** — `d5_migrate`
   (`src/port_wasm_units.py:2936-3104`): local-only commit of the registry
   (`port-registry: D5-6 migration revocations ...`, 3088-3100), never
   pushes; the next sanctioned flow carries it.
6. **The workflow journal** — `src/port_progress.py`: a **separate, orphan**
   branch named `port-progress` (seeded by plumbing with no parent,
   `_seed_branch`, `port_progress.py:301-364`), written through a dedicated
   worktree `<repo>/.tmp/port-progress-worktree`
   (`port_progress.py:13-16, 250-251`), one compact `workflow-progress/`
   tree, committed on every unit transition and pushed with an explicit
   refspec `git push origin port-progress:port-progress`
   (`flush_pending_push`, `port_progress.py:926`). Push failures are
   recorded in `pending-push.json` and retried on later transitions
   (`port_progress.py:914-959`); the driver also retries at run
   start/end (`_flush_pending_progress`,
   `src/port_wasm_units.py:3777-3782`). Non-fast-forward reconciles with
   `merge -X ours` (935-945); unrelated histories re-seed from the remote
   (946-955).

### 1.3 The contamination, quantified

`origin/main` == local `main` == `8987031e` at survey time — and that tip
commit is itself an artifact commit (`port-assembly: gate N=5 FAIL`). The
interleaving starts at split point **`45db9ff1`** ("poc: verbatim-C→wasm POC
executed E2E", 2026-08-09) — the parent of the first artifact commit
(`b2f8d88a`, `port: damage-core wasm unit green`). Since the split:
**109 commits on `main` = 73 artifact commits + 36 engineering commits,
interleaved** (subjects `port-staging:` / `port-assembly:` /
`port-registry:` / `port: <name> wasm unit ...`). The tracked artifact
surface in `main`'s tree today: 168 files under
`research/decomp/port-units/` + `research/decomp/port-units-staging/`, plus
`knowledge-registry.json`, `research/decomp/data/assembly-gate.json`, and
`research/decomp/data/oracle-results/*.json`.

Note the two-layer failure: the *bare-push bug* (item 3 above) merely
exposed the deeper design fact that the driver's whole commit lineage IS
`main` — fixing the bare push (done, `_push_product`) still leaves every
artifact commit on the `main` lineage and pushes them to `origin/main`
deliberately. Lineage separation, not push hygiene, is the cure.

## 2. Target topology

Three lineages, two repos:

| Lineage | Repo | Contents | Writer |
|---|---|---|---|
| OGhidra `main` (upstream: `fork/main`) | OGhidra | driver/tool engineering | humans/agents, review-pass |
| GotYaForce `main` | GotYaForce | engineering + product code + certified final-build content | humans/agents on review-pass; the §4 promotion command |
| GotYaForce `port-progress` | GotYaForce | `main` + artifacts (staging trees, promoted units, registry, ledgers, journal) | the driver, exclusively |

### 2.1 Which repo gets the worktree — GotYaForce, and only GotYaForce

The artifacts live in GotYaForce; therefore the dedicated worktree is a
**GotYaForce** worktree. The OGhidra repo needs no topology change at all:
the driver tool's own code keeps landing on OGhidra `main` → `fork/main`
on review-pass exactly as today (AGENTS.md "Git traps"); nothing the driver
does at runtime writes the OGhidra repo. Stating this precisely because the
two repos are physically nested and the survey found agents conflating them
before: `repo_root` in the driver is ALWAYS the GotYaForce root
(`find_gotyaforce_root()`, `src/port_wasm_units.py:1218-1220`), never the
OGhidra checkout.

**The artifact worktree:** `<gotyaforce>/.tmp/port-progress-worktree`,
checked out on branch `port-progress`. This is the journal's existing
worktree path and branch name, deliberately: the journal already proves
every mechanism the artifact writer needs (health check with stale
`index.lock` detection, double-`--force` removal of locked worktrees,
idempotent `prepare()` — `port_progress.py:366-430`), and §2.2 folds the
two writers into one lineage so there is exactly one push channel to watch.

**Path re-rooting (driver change, OGhidra repo):** every path the driver
WRITES as tracked content resolves against the artifact worktree instead of
`repo_root`:

- `artifact_root` → `<worktree>/research/decomp/port-units`
- `staging_root` → `<worktree>/research/decomp/port-units-staging`
- `registry_path` → `<worktree>/research/decomp/generated/finish-game-port/knowledge-registry.json`
- `assembly_ledger_path` (its tracked half after the §5 split) → `<worktree>/research/decomp/data/...`

(today all four resolve against `repo_root`:
`src/port_wasm_units.py:1225-1226, 1256, 1268-1270`). Everything the driver
only READS (queue files, seed header, PoC harness, oracle cwds) and
everything untracked (run_root state, work_root scratch) stays on
`repo_root` — the worktree merges `main` in (§2.3), so read paths are
present in both and reading from `repo_root` keeps the main worktree the
single source for inputs. `_git` grows a sibling `_git_wt` that runs in the
worktree (the journal's exact pattern, `port_progress.py:287-288`); ALL
artifact add/commit/push calls move to it. The rejected alternative —
keep writing under `repo_root` and rsync into the worktree at commit time —
was rejected for the dual-copy drift it invites: T3 reverify reads the
"committed staged artifact" (`src/port_wasm_units.py:3296-3297`), and two
copies of a staging tree with independent lifetimes is how a reverify runs
against the wrong bytes.

### 2.2 One artifact lineage: `port-progress` = `main` + artifacts + journal

The branch is **based on `main`** (branched at the migration tip, §6), not
orphan: units build against seed headers, queue files, and the PoC harness,
and the §4 promotion path needs artifact paths to be plain
checkout/cherry-pick targets — both require the artifact lineage to contain
the product tree. This retires the current orphan journal branch of the
same name (migration step, §6.1).

The journal folds into the same lineage: `ProgressJournal` keeps its own
commit cadence (every transition) and its pending-push machinery unchanged,
but its worktree and branch are now shared with the artifact writer. Effects:

- **One push channel.** Per-unit artifact pushes are the heartbeat; journal
  checkpoint pushes ride the same branch, so a red-only night still pushes
  (journal commits), preserving the original purpose of the journal
  (`port_progress.py:1-27`) with zero extra branches.
- **Mutual carry-forward.** A failed artifact push is carried by the next
  journal push and vice versa — branch pushes carry all local commits.
  This *strengthens* today's G3 carry-forward (§7 I3).
- **One new contention point, named and handled:** two writers now share
  one index. Today the driver commits in the main worktree and the journal
  in its own worktree, so they never contend; post-migration, artifact
  commits MUST take the journal's `progress.lock`
  (`port_progress.py:261, 703-712`) around add/commit/push. The journal's
  contended behaviour (skip + replay from the local mirror) stays; the
  artifact writer's contended behaviour is **bounded wait then fail the
  commit as today's commit-failure path** (`sha is None` → unit NOT
  settled, `src/port_wasm_units.py:2652-2660`) — never skip, because an
  artifact commit is settle-critical. The supervisor's
  `port-contract checkpoint` writer inherits the same lock unchanged.

### 2.3 Tracking driver-code and input updates from `main` — merge forward, never back

`port-progress` consumes `main` (queue regenerations, seed-header changes,
oracle-spec updates, product-code changes the assembly gate links against)
by **merging `main` into `port-progress`**:

- **When:** at driver start, inside `prepare()`, whenever
  `git rev-parse main` differs from a `last-merged-main` marker file kept in
  the worktree's journal dir; and unconditionally at supervisor recycle.
  The driver "ports one unit per run" (AGENTS.md), so this is effectively
  per-unit — cheap, because it is a no-op merge whenever `main` did not
  move.
- **Direction invariant:** `main` is NEVER merged from, rebased onto, or
  fast-forwarded to `port-progress`. There is no code path that does it;
  the §7 guard tests enforce that no driver/journal git call names `main`
  as a push destination or merge target of `port-progress`.
- **Conflicts:** artifact paths and engineering paths are disjoint by the §5
  policy, so the merge is expected to be trivial forever. A conflicting
  merge is therefore a policy breach, not a merge problem: the driver
  REFUSES to start, aborts the merge, and pages
  (`block_reason=port_progress_merge_conflict` through the existing journal
  machine-state channel) rather than auto-resolving. `-X ours`/`-X theirs`
  auto-resolution is explicitly rejected for this merge — silently
  discarding either side of a conflict that cannot legitimately exist would
  bury the breach the conflict is reporting. (The journal's existing
  `-X ours` reconcile for its OWN generated files on non-fast-forward,
  `port_progress.py:935-945`, is unchanged — that resolves two machine
  journals racing, not engineering vs artifacts.)

## 3. The push matrix

The complete set of sanctioned pushes. **Anything not in this table does not
push. Every push carries an explicit `<remote> <refspec>`.**

| # | Repo | Remote:branch | Trigger | What rides it | Exact form |
|---|---|---|---|---|---|
| P1 | OGhidra | `fork` : `main` | engineering change passes review | driver/tool code, docs, tests | `git push fork main:main` |
| P2 | GotYaForce | `origin` : `main` | engineering/product change passes review | product code, queue/spec inputs (§5 class A) | `git push origin main:main` |
| P3 | GotYaForce | `origin` : `main` | §4 certified promotion, owner-triggered | the certified unit's final-build content, nothing else | `git push origin main:main` (issued by the promotion command, main worktree) |
| P4 | GotYaForce | `origin` : `port-progress` | per-unit staging/green/promotion commit — **the G3 heartbeat** | unit artifact tree + registry co-commit; any local ledger/journal commits accumulated since the last push | `git push origin port-progress:port-progress` (from the artifact worktree) |
| P5 | GotYaForce | `origin` : `port-progress` | journal checkpoint (every transition) / pending-push flush | journal tree; carries any unpushed artifact/ledger commits | same refspec as P4 (`port_progress.py:926` already has it) |

Explicitly NOT pushes, unchanged from today's fixed code: assembly-gate
ledger commits (local, ride P4/P5 — `src/port_wasm_units.py:1882-1885`),
d5-migrate registry commits (local, ride P4/P5 —
`src/port_wasm_units.py:3090-3091`), and the maintenance CLIs
(`reverify --dry-run`, replay: "Never pushes",
`src/port_wasm_units.py:4133`).

`_push_product` (`src/port_wasm_units.py:1988-2000`) is renamed/re-specced
to P4: `git push origin port-progress:port-progress`, executed by `_git_wt`
in the artifact worktree. Its current form (`push origin HEAD`) is correct
push-hygiene for the wrong lineage: `HEAD` in the main worktree is `main`,
so it implements the superseded runbook invariant. Under this design a
push of the current branch by indirection (`HEAD`) is also banned in driver
code — the refspec names the branch literally, so a wrong-worktree
invocation fails loudly instead of pushing whatever was checked out (§7 G2).

Supersession note (must land with the migration, or the monitor pages
forever): AGENTS.md's monitoring invariant "`main` should receive a push
whenever a unit goes green" and the `_push_product` docstring both encode
main-as-heartbeat. Both are rewritten to name `origin/port-progress` as the
heartbeat ref. The rig-side push-silence cron (ownership caveat:
compile-fix-loop-design.md §4 — the cron lives on the rig supervisor; this
repo can request, not attest) must repoint at `origin/port-progress`.

## 4. Certified promotion: the ONLY artifact→`main` writer

Two promotions exist and must not be conflated:

- **T3 verification promotion (staging → port-units)** — already
  implemented (`_reverify_unit_inner`), stays entirely **on the artifact
  lineage**: post-migration it commits and pushes on `port-progress` (P4).
  A verified unit is inventory, not product.
- **Certified promotion (artifact lineage → `main`)** — the subject of this
  section. New, explicit, and the sole writer under R4.

**Trigger — owner-triggered, machine-gated.** Chosen over
T3-verified-auto-promotion deliberately: T3 pass is a per-unit claim
("this unit's oracle passed"), while `main` membership is a product claim
("this content is part of the final build"). The second claim is not
derivable from the first — a verified unit that no build consumes is still
inventory. So promotion is a command the owner runs
(`python -m src.port_wasm_units promote-to-main --unit <name> ...`,
batchable), and the command **refuses** unless every precondition below is
machine-checked true. The owner cannot override a failed precondition from
the command line; a false precondition is fixed upstream, not waived.

**Preconditions (all must hold, all machine-checkable):**

1. **Oracle-verified:** the unit's state tier is `oracle_green` with a
   `verify.status == "pass"` record from the T3 queue
   (`src/port_wasm_units.py:3496-3510`), and the journal contains the
   corresponding `verdict_promoted` event — the settle-through-journal rule
   (compile-fix-loop-design.md §2.9 [V4-9]) applies to certification
   doubly.
2. **Assembly-gate clean:** the unit is inside the most recent PASSING gate
   window (`last_run` in the gate ledger — not `largest_n_passed`, which is
   a high-water mark by design and overstates current composability,
   compile-fix-loop-design.md §2.13 advisories), and no OPEN conflict
   record implicates the unit or any symbol it defines.
3. **Part of the actual build:** the unit is referenced by the final-build
   link manifest (the assembly workstream's product — the §2.13 gate's
   merged-header/link plan consuming registry `dat_typing`/`prototype`
   entries). A unit no build input names does not promote, whatever its
   tier.
4. **Clean landing:** the promotion commit is made in the **main worktree**
   on `main`, contains exactly the certified content for the named unit(s)
   (pathspec'd, as every driver commit already is), with a
   `promotion-provenance` record naming the source `port-progress` commit
   sha — so `main`'s history states, per certified file, which artifact
   commit it was certified from. Push is P3, explicit refspec.

What certified content IS (owner-visible definition, so review can check
promotions against it): the final-build form of the unit — the reconciled
header/`.c`/wasm as the build consumes it, plus provenance. What it is NOT:
the staging tree, iteration headers, oracle logs, ledgers, or state — those
never leave `port-progress`.

## 5. Tracked-file policy

Three classes. The test is mechanical: who writes it, and when.

**Class A — engineering inputs (tracked on `main`, land via review-pass
P2):** human/agent-authored or generator-produced-and-reviewed inputs the
pipeline consumes. `wasm-units.json`, `wasm-units-skipped.json`,
`wasm-units-migration.json`, `gnt4_shim_seed.h` (all currently tracked in
the negation-excepted `finish-game-port/` dir), `unit-priority.json`,
`oracle-commands.json`, `oracle-registry.json`, and the builder scripts in
`research/decomp/data/`. Rationale: they change on reviewed regeneration
events (Tier-0 style), not per-unit; the driver only reads them; and
keeping them on `main` means `port-progress` receives them through the §2.3
merge like any other input.

**Class B — machine-written artifacts (tracked on `port-progress` ONLY):**
everything the driver writes as a tracked file at run time.
`research/decomp/port-units/`, `research/decomp/port-units-staging/`,
`knowledge-registry.json` (the [V4-8] gitignore negation stays — the path
must remain trackable, and the same `.gitignore` governs the worktree; only
the branch it is tracked ON changes), the assembly conflict ledger (below),
`research/decomp/data/oracle-results/`, and the journal's
`workflow-progress/` tree. `main`'s copies of these are removed at
migration (§6).

**Class C — run-status churn (untracked, any branch):** files that change
on every run or every call and answer "what is happening now", not "what
was decided". Already untracked by the wholesale ignore of the run root
(GotYaForce `.gitignore:63/70`): `wasm-units-state.json`, `run-state.json`,
`events.jsonl`, `llm-liveness.json`, `pending-push.json`, `progress/`
local mirrors. This design adds **the assembly-gate split** the churn
analysis demands: `record_gate_result` stamps `last_run`/`updated_at` on
every call, which is why the current code commits the file only on material
change (`src/port_wasm_units.py:1876-1885`) — a workaround that leaves the
working tree perpetually dirty between material changes. Replace with two
files: `assembly-conflicts.json` — conflict RECORDS + `largest_n_passed`,
Class B, committed on material change exactly as today's predicate — and
`assembly-status.json` — `last_run`/timing churn, Class C, untracked,
gitignored. The ledger commit becomes clean-tree-preserving instead of
materiality-filtered-by-necessity.

Classification rule for future files, so this table does not rot: a file
the driver writes during a run is Class B if a later run or the assembly
workstream must read the *decision* it records, Class C if only dashboards
read it, and never Class A.

## 6. Migration

Ordered steps. Steps 1–5 are mechanical and this design's to execute
(driver paused throughout); step 6 is the **owner's decision**, presented
as options with tradeoffs, deliberately not chosen here.

**6.0 Pause.** The one correct way: manual gate paused, wait for
`driver_pid: null` (AGENTS.md). Everything below happens with no driver and
no supervisor checkpoint writer running (disable the scheduled task per the
GPU-work runbook so `port-contract checkpoint` cannot race the worktree
surgery).

**6.1 Retire the orphan journal branch.** The name `port-progress` is
currently an orphan journal lineage (`port_progress.py:301-364`); the
target design reuses the name for the artifact lineage. Sequence:

1. Archive: `git branch port-journal-archive port-progress` and
   `git push origin port-journal-archive:port-journal-archive` — the old
   journal history stays reachable forever under a new name.
2. Remove the journal worktree
   (`git worktree remove --force .tmp/port-progress-worktree`; twice with
   `--force` if locked, the code's own trick, `port_progress.py:399-405`).
3. Re-point the branch: `git branch -f port-progress <current main tip>`.
4. Carry the journal tree forward: check the new branch out in the
   recreated worktree, copy `workflow-progress/` from
   `port-journal-archive` into it, one commit
   (`journal: carry workflow-progress history onto the merged lineage`).
   The journal's rolling-window design (2,000-event cap,
   `port_progress.py:54-56`) means this is small by construction.
5. Replace the remote branch: `git push origin
   +refs/heads/port-progress:refs/heads/port-progress` — a one-time,
   owner-executed forced replacement of a machine journal with no
   downstream consumers. **Ordering matters:** this must complete before
   anything unpauses, because the journal's unrelated-histories handler
   (`port_progress.py:946-955`) auto-adopts the REMOTE journal — a
   half-migrated remote would fight the local migration and win.

**6.2 Land the driver changes (OGhidra repo, review-pass, P1):** path
re-rooting (§2.1), `_git_wt` + `progress.lock` around artifact commits
(§2.2), merge-forward at prepare/recycle (§2.3), `_push_product` → P4
refspec (§3), the assembly-gate file split (§5), the §7 guard tests, and
the AGENTS.md / monitoring supersessions (§3). The `settle-unit` CLI and
`d5-migrate` re-root with the driver (their commits become `port-progress`
commits automatically — they already go through `_commit_paths`/the
registry path).

**6.3 First artifact-lineage run.** Unpause; the first unit's P4 push is
the proof: `origin/port-progress` gains a staging commit,
`origin/main` gains nothing.

**6.4 Remove Class-B files from `main`'s tree** (this is NOT the history
decision): one reviewed commit on `main` deleting
`research/decomp/port-units/`, `research/decomp/port-units-staging/`,
`knowledge-registry.json`, `assembly-gate.json`,
`research/decomp/data/oracle-results/`; message states they live on
`port-progress` henceforth. Because `port-progress` branched from a tip
that CONTAINS these files, the §2.3 merge of this deletion commit would
delete them on `port-progress` too — so this commit merges into
`port-progress` with the artifact paths explicitly restored in the merge
commit (`git checkout HEAD -- <paths>` before committing the merge), a
one-time documented exception to the trivial-merge expectation, executed by
hand as part of migration, not by the driver.

**6.5 The split point, stated for the record.** `port-progress` starts at
the migration-day `main` tip, so both lineages share all history up to it —
including the 73 interleaved artifact commits since `45db9ff1`
(2026-08-09). Nothing about the new lineage depends on cleaning that
history; only `main`'s owner-facing cleanliness does. Hence:

**6.6 OWNER DECISION — what to do about `origin/main`'s interleaved
history.** Two options; this design recommends neither.

**Option A — revert-forward (keep history, clean the tree).** Step 6.4 is
the whole cleanup: artifacts vanish from `main`'s TREE; the 73 artifact
commits remain in `main`'s HISTORY permanently.

- For: no force-push; every clone, PR baseline, CI cache, and cross-repo
  SHA citation stays valid (design docs already cite GotYaForce SHAs, e.g.
  `9fccede` in compile-fix-loop-design.md — Option A keeps every such
  citation resolvable on `main`); zero coordination cost; reversible
  never needed.
- Against: R1 holds only from migration day forward — `git log main`
  forever interleaves 73 artifact commits through the 2026-08-09..20
  window; repo size keeps the artifact blobs on every `main` clone
  (bounded: today's artifact surface is 168 files plus history — modest,
  but it never shrinks); "artifacts never on main" is a tree invariant,
  not a history invariant.

**Option B — rewind and rebuild (clean history, pay for it).**
`main` is rebuilt: reset to split point `45db9ff1`, cherry-pick the 36
engineering commits since (they are content-disjoint from the artifact
commits, so cherry-picks apply cleanly), then
`git push --force-with-lease origin main:main`.

- For: R1 holds retroactively — `main`'s history contains no artifact
  commit at all; log/blame/bisect on `main` are clean through the
  contamination window; artifact blobs eventually gc out of fresh `main`
  clones.
- Against: a force-push of the product branch — every clone and open
  branch based on post-split `main` must rebase; **all 36 engineering
  commits get new SHAs**, so every recorded citation of a post-split
  GotYaForce SHA (design docs, journal `product_commit` fields, memory
  notes) silently dangles; and the interaction with `port-progress` is
  permanent: `port-progress` branched from the OLD tip, so after the
  rewind, every §2.3 merge of new `main` re-introduces the 36 commits as
  duplicate-content, different-SHA history — merges stay conflict-free
  (identical patches) but `port-progress`'s log carries both copies
  forever. Alternative sub-option (rebase `port-progress` onto the rebuilt
  `main` too) makes the artifact lineage's own early history rewritten as
  well, dangling the journal's recorded artifact SHAs. Either way,
  something's recorded SHAs break; Option B is choosing WHICH.
- If B is chosen, ordering: the rewind must complete before 6.3's first
  driver run, and 6.4/6.5 adjust accordingly (the Class-B deletion commit
  is part of the rebuild, and `port-progress` should then branch from the
  REBUILT tip + one commit re-adding the artifact trees from the old tip —
  keeping the artifact lineage single-copy).

The decision gates on one question only the owner can weigh: is retroactive
history cleanliness on `main` worth breaking every post-2026-08-09 SHA
reference and force-pushing the product branch once. Both options satisfy
R1's tree form and everything else in this design.

## 7. Failure modes and invariants

| # | Invariant / failure mode | Handling | Enforced by |
|---|---|---|---|
| I1 | Every push names `<remote> <refspec>` literally; no bare `git push`, no `HEAD` push in driver/journal code | design rule §3 | **guard test G1** |
| I2 | G3 heartbeat: per-unit push on `origin/port-progress`; push silence > threshold ⇒ RCA | thresholds unchanged from compile-fix-loop-design.md §4; monitored ref repointed | rig cron (request-not-attest caveat) + AGENTS.md rewrite |
| I3 | Push-failure carry-forward, exactly today's semantics: push failure ≠ commit failure; the unit settles with `pushed=False` and the NEXT branch push (P4 or P5) carries it; commit failure ⇒ unit NOT settled (`src/port_wasm_units.py:2652-2660`); journal pending-push file + flush retries unchanged (`port_progress.py:914-962`, `src/port_wasm_units.py:3777-3782`) | preserved verbatim; the shared lineage strengthens it (any later push carries everything) | existing tests + G4 |
| I4 | Worktree lock vs driver lock: `wasm-units.lock` serializes drivers (unchanged); `progress.lock` serializes ALL writes in the shared worktree (§2.2) — driver artifact commits acquire it with bounded wait, journal keeps skip+replay | §2.2 | new unit test: concurrent checkpoint + artifact commit never interleave in one index |
| I5 | Supervisor recycle / tree-kill mid-commit leaves `index.lock` in the shared worktree | `_worktree_healthy` already detects exactly this and `prepare()` rebuilds (`port_progress.py:372-381`) — kills are the NORMAL stop path and stay safe | existing journal tests extended to the artifact writer |
| I6 | Merge `main`→`port-progress` conflicts | refuse start + page, never auto-resolve (§2.3) | driver start path |
| I7 | Nothing merges/pushes `port-progress`→`main` except the §4 command | one writer, preconditions machine-checked | **guard test G2** + review |
| I8 | `origin/main` receives an artifact commit anyway (regression) | RCA, not waiting | **guard test G3** (monitor-side) |
| I9 | Non-fast-forward on `origin/port-progress` (second machine/worktree) | journal files: `-X ours` reconcile as today; artifact paths conflicting in that merge ⇒ two artifact writers exist ⇒ page, do not resolve | `flush_pending_push` extension |
| I10 | Worktree deleted/corrupted mid-campaign | `prepare()` rebuilds from the branch; committed artifacts are safe (they are commits, not worktree files); in-flight uncommitted unit artifacts are re-derived by the unit re-running (retryable, §2.10 semantics) | journal precedent |
| I11 | Settle-through-journal (compile-fix-loop-design.md §2.9) applies to every lineage operation here: promotion, certification, migration each emit their journal event | §4, §6 | AGENTS.md rule, review |

**Guard tests (OGhidra `tests/`, alongside the existing no-vendor-branding
guard that AGENTS.md cites as precedent):**

- **G1 — no push without explicit refspec:** parse
  `src/port_wasm_units.py`, `src/port_progress.py`, `src/port_contract.py`,
  `src/incremental_port.py` for git invocations whose argv contains
  `"push"`; assert every one carries ≥2 following args (remote + refspec)
  and the refspec contains a literal branch name (`:` form or
  `refs/heads/`), rejecting `HEAD` as a source. This greps CODE, not
  history — it catches the next bare push before it runs.
- **G2 — no artifact→main writer outside promotion:** assert no git
  invocation in driver/journal code pushes to `main` or merges
  `port-progress` except inside the `promote-to-main` command's module
  scope.
- **G3 — main-cleanliness monitor (GotYaForce side, cron/CI):**
  on every new `origin/main` commit, fail if it touches a Class-B path or
  its subject matches the artifact classes
  (`^port-staging:|^port-assembly:|^port-registry:|^port: .* wasm unit `),
  excluding commits carrying §4 promotion provenance.
- **G4 — carry-forward regression:** simulate a failed P4 push; assert the
  unit settles `pushed=False`, and the next P5 journal push lands the
  artifact commit on the remote.

## 8. Goals traceability

| Requirement | Served by |
|---|---|
| R1 artifacts never on `main` | §2 lineage split; §5 class policy; §6.4 tree cleanup; §6.6 (owner) history cleanup; G3 monitor |
| R2 G3 heartbeat preserved | §3 P4/P5 single channel; I2, I3, G4; journal fold-in (§2.2) keeps red-night visibility |
| R3 explicit refspecs everywhere | §3 matrix; G1 |
| R4 one certified writer to `main` | §4; I7; G2 |
| R5 repo precision | §2.1 (GotYaForce worktree; OGhidra unchanged); §1.1 |
