# Git topology redesign — lineage separation for port artifacts (v2, rev. 2026-08-21)

Status: v1 was adversarially reviewed — PASS with required changes F1–F9;
v2 applies all nine, marked `[F#]` at each change site. No code in this
document has been implemented; every "current code" claim below was
re-verified in-repo on 2026-08-21 with file:line citations, **re-pinned
against OGhidra `ff71f52` and GotYaForce `ef6767bf`** (the concurrent
bare-push audit has now fully landed, so the v1-era "line numbers are
drifting under us" caveat is retired: the citations below are exact as of
those two commits, and function names remain the stable fallback). The
reviewer confirmed §1's reading of the lineages (artifact commits ride
`main`; `port-progress` is a pure generated journal); one surveying trap
is recorded for future audits: the `rtk` CLI proxy truncates long
`git log` output, which is how a "mixed journal head" misreading arose
elsewhere — use `rtk proxy git log` (raw passthrough) for history
censuses.

**Landed since v1 (this document must describe them as current reality,
not as proposals):**

- OGhidra `376c553` — explicit refspec for the D8 batch push
  (`src/port_driver.py`, + regression test
  `tests/test_port_driver.py:494-516`). Remote is now named; the source is
  still `HEAD` (§1.2 item 7a).
- OGhidra `ff71f52` — **interim**: `_push_product` now pushes
  `origin HEAD:refs/heads/port-staging` instead of the current branch's
  same-named origin branch. Greens, promotions, ledgers and registry
  co-commits no longer reach `origin/main` at all.
- GotYaForce `ef6767bf` — AGENTS.md monitoring invariant rewritten to
  match: "origin `port-staging` should receive a push whenever a unit goes
  green ... pending docs/git-topology-design.md". The interim is therefore
  *documented owner policy*, not a stray patch, and this design owns its
  termination (§2.0, §6.3).

The owner directive (binding, restated):

> Port artifacts — staging trees, ledgers, status/state JSON, registries,
> oracle evidence — must NEVER appear on GotYaForce `main`. `main` is
> engineering + product code + certified final-build content only.

And the standing goals it must be reconciled with (compile-fix-loop-design.md
§0): **G3 — git pushes are the heartbeat; absence must mean breakage,
detectably.** Until `ff71f52` the heartbeat was implemented by pushing
artifact commits to `origin/main` (AGENTS.md's original monitoring
invariant: "`main` should receive a push whenever a unit goes green") —
i.e. the owner directive and G3 were served by the same push, which is
exactly why they came into conflict. The interim severed that push from
`main` and pointed it at `origin/port-staging` (§2.0), which relieves the
directive without yet satisfying it. The cure is lineage separation: the
heartbeat moves to a dedicated, permanent artifact lineage, and `main`
receives artifacts only through one explicit, certified promotion path.

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
   (`src/port_wasm_units.py:1988-2006`, re-targeted by `ff71f52`):
   `refspec = "HEAD:refs/heads/port-staging"`, `git push origin <refspec>`
   with one retry — an **owner-ordered INTERIM** (its docstring says so,
   naming this document as the pending disposition): the local commit
   lineage is unchanged (still `main`), the push lands on an interim
   `origin/port-staging` branch, and `origin/main` receives nothing.
   §2.0, §3 and §6.3 state how that branch folds into the target
   topology [F4].
3. **T2b assembly-gate ledger commits** — `_maybe_run_assembly_gate`
   (`src/port_wasm_units.py:1834-1908`): after every green, on MATERIAL
   ledger change only, a local pathspec'd commit of
   `research/decomp/data/assembly-gate.json`, message `port-assembly: gate
   N=<n> pass|FAIL ...`, **no push** — it rides the next sanctioned push.
   The comment at 1873-1885 records that a bare push here was the
   `origin/main` contamination vector.
4. **T3 promotion commits** — `_reverify_unit_inner`
   (`src/port_wasm_units.py:3298`ff) via `_commit_paths`
   (`src/port_wasm_units.py:3273`ff, pushes through `_push_product`):
   on oracle pass, copy staging → `research/decomp/port-units/<name>`,
   commit `port: <name> wasm unit promoted (oracle <summary>)`
   (`:3461`) with the registry promotion co-commit, write the
   `verify` record (`:3468`), journal, then a separate deletion commit
   `port: remove staged copy of promoted unit <name>`
   (`_remove_staged_copy`, `src/port_wasm_units.py:3540`, message at
   `:3549`). On oracle red, a registry revocation commit
   `port-registry: revoke <name> entries (staged oracle re-run failed)`
   (`:3367`) with its own `verify` record (`:3338`, `:3383`).
5. **d5-migrate registry revocations** — `d5_migrate`
   (`src/port_wasm_units.py:2942`ff): local-only commit of the registry
   (`port-registry: D5-6 migration revocations ...`, `:3102`), never
   pushes; the next sanctioned flow carries it.
6. **The workflow journal** — `src/port_progress.py`: a **separate, orphan**
   branch named `port-progress` (`PROGRESS_BRANCH`, `:51`; seeded by
   plumbing with no parent, `_seed_branch`, `port_progress.py:301-364`),
   written through a dedicated worktree `<repo>/.tmp/port-progress-worktree`
   (`port_progress.py:10-16, 250-252`), one compact `workflow-progress/`
   tree (`PROGRESS_DIR`, `:52`; bounded at `MAX_EVENT_LINES = 2000`,
   `:54-56`), committed on every unit transition and pushed with an
   explicit refspec `f"{self.branch}:{self.branch}"`
   (`flush_pending_push`, `port_progress.py:914`, push at `:926`). Push
   failures are recorded in `pending-push.json` and retried on later
   transitions (`:914-960`); the driver also retries at run start/end
   (`_flush_pending_progress`, `src/port_wasm_units.py:3783`).
   Non-fast-forward reconciles with `merge -X ours` (`:937-939`, retry
   push `:941`); unrelated histories re-seed from the remote
   (`:946-955`, `worktree remove --force` `:952` + `branch -D` `:953`).
7. **[F4] Two push sites OUTSIDE the wasm-unit driver**, missed by v1's
   survey: (a) `port_driver.py` `_batch_push`
   (`src/port_driver.py:763-800`) — the source-loop driver's one-per-run
   push, called from the `run()` `finally` block (`:760`). `376c553` gave
   it an explicit remote and a regression test
   (`tests/test_port_driver.py:494-516`, asserting exactly
   `("git", "push", "origin", "HEAD")`), but the source is still `HEAD`,
   which resolves to `main` in the main worktree, and unlike
   `_push_product` it was NOT redirected by `ff71f52` — so `_batch_push`
   is today the one remaining driver path that would put artifact-class
   content on `origin/main` if the source loop ran; (b)
   `incremental_port.py` (`src/incremental_port.py:427-433`) — the legacy
   cumulative two-unit TS transaction, `git push origin
   HEAD:refs/heads/main` from its own disposable worktree, reachable not
   only from its test but from the CLI as `prove-incremental-port`
   (`main.py:1303-1306`). Both are dispositioned in §3.

   Guard-coverage reality check: there is **no cross-file push audit test
   today**. The two pushes above and `_push_product` each have a
   single-site regression test; the only cross-file source scan in the
   tree is the no-console-window guard
   (`tests/test_port_wasm_progress.py:405-426`), whose file list
   (`port_wasm_units.py`, `port_progress.py`, `port_driver.py`) is the
   structural precedent G1 extends (§7).

### 1.3 The contamination, quantified

`origin/main` == `8987031e` (`git ls-remote origin`, 2026-08-21) and that
tip commit is itself an artifact commit
(`port-assembly: gate N=5 FAIL (1 conflict(s)) after auto-c0035-006`).
`origin/main` has not moved since the interim landed — the driver is
paused. Local `main` is `ef6767bf` (one unpushed ENGINEERING commit ahead:
the AGENTS.md interim update itself).

The interleaving starts at split point **`45db9ff1`** ("poc: verbatim-C→wasm
POC executed E2E", 2026-08-09) — the parent of the first artifact commit
(`b2f8d88a`, `port: damage-core wasm unit green`). Since the split:
**110 commits on local `main` = 73 artifact commits + 37 engineering
commits, interleaved** (artifact subjects `port-staging:` /
`port-assembly:` / `port-registry:` / `port: <name> wasm unit ...`; v1
counted 109/36 before `ef6767bf`, and the engineering count keeps growing
while the gate is paused — §6.6 Option B's cherry-pick set is therefore
"the engineering commits since the split", not a frozen 36). The tracked
artifact surface in `main`'s tree today: **168 files** under
`research/decomp/port-units/` + `research/decomp/port-units-staging/`
(`git ls-files`), plus `knowledge-registry.json`,
`research/decomp/data/assembly-gate.json`, and the three
`research/decomp/data/oracle-results/*.json`.

Note the two-layer failure: the *bare-push bug* (item 3 above) merely
exposed the deeper design fact that the driver's whole commit lineage IS
`main`. `ff71f52` fixed the push hygiene and the destination — the
heartbeat now lands on `origin/port-staging`, `origin/main` receives
nothing — but every artifact commit still accumulates on the LOCAL `main`
lineage, uncleanly separable, and `main`'s tree still carries the whole
artifact surface. The interim moved the leak, not the contamination.
Lineage separation, not push hygiene, is the cure.

## 2. Target topology

Three lineages, two repos:

| Lineage | Repo | Contents | Writer |
|---|---|---|---|
| OGhidra `main` (upstream: `fork/main`) | OGhidra | driver/tool engineering | humans/agents, review-pass |
| GotYaForce `main` | GotYaForce | engineering + product code + certified final-build content | humans/agents on review-pass; the §4 promotion command |
| GotYaForce `port-progress` | GotYaForce | `main` + artifacts (staging trees, promoted units, registry, ledgers, journal) | the driver, exclusively |

### 2.0 Three branch names are in play — the reconciliation

The interim (`ff71f52` + `ef6767bf`) introduced a third GotYaForce branch
name, so a reader can now find three plausible "where do artifacts go"
answers in the tree. They are reconciled here explicitly, because two of
the three are temporary and both disappear into the third.

| Name | What it is TODAY | Lineage | Remote state (2026-08-21) | What happens to it |
|---|---|---|---|---|
| `port-staging` | the **interim push target**: greens/promotions/ledgers commit on local `main` as always, and `_push_product` pushes that `main` lineage to `origin port-staging` (`src/port_wasm_units.py:1988-2006`) | local `main` — the interim changed only the *destination*, never the commit lineage | **does not exist yet.** `git ls-remote origin` returns only `refs/heads/main`, `refs/heads/port-progress`, `refs/pull/1/head`. The gate has been paused since before the first post-`ff71f52` green, so the branch is created by the first green after the gate resumes | **retired at migration** (§6.3). It is a prefix of the lineage the new `port-progress` starts from, hence strictly redundant after the first P4 push |
| `port-progress` (today) | the **orphan generated journal** — no parent, one `workflow-progress/` tree, its own worktree (`port_progress.py:301-364`, `:250-252`) | orphan, shares NO history with `main` | exists: `f31eef15` | **archived and superseded** at migration: renamed `port-journal-archive`, its content carried onto the new lineage (§6.1) |
| `port-progress` (target) | the **artifact lineage** this design specifies: `main` + artifacts + journal, one worktree, one push channel, the G3 heartbeat | branched FROM `main` at the migration tip | created by §6.1 step 3 | permanent |

The name collision is deliberate and load-bearing: the target lineage
**reuses the name `port-progress`** so that exactly one artifact ref name
exists on the remote at the end, and so the journal's existing worktree
plumbing, branch constant (`PROGRESS_BRANCH`, `port_progress.py:51`) and
push refspec need no renaming. The cost is that "`port-progress`" means
two different things across the migration boundary — hence the archive
branch, hence §6.1's strict ordering, and hence the rule that no document
may say "the port-progress journal branch" post-migration without
qualification. AGENTS.md's "Git traps" bullet ("machine journal on
`port-progress`") is one such statement and is rewritten by §6.2 alongside
the monitoring invariant.

**Why the interim is not simply left in place.** `port-staging` solves
exactly one of the five requirements — R1's remote half. It leaves R1's
local half unsolved (`main`'s tree and lineage still carry artifacts,
§1.3), R3 partially unsolved (`_batch_push` still pushes `HEAD`, §1.2
item 7a), R4 entirely unsolved (there is no certified promotion path; the
interim just severs `main` rather than gating it), and it splits the
heartbeat across two remote refs — `origin/port-staging` for greens,
`origin/port-progress` for journal checkpoints — which is why a monitor
watching either one alone can now miss a class of stall. The target
topology re-merges those into one ref (§3 P4/P5).

**Interim-period invariant (binding until migration):** while the interim
runs, `origin/port-staging` is the green heartbeat and
`origin/port-progress` is the journal heartbeat; *both* are watched, and
neither may be repointed at `main`. AGENTS.md `ef6767bf` names the first;
the second is the pre-existing journal push.

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
every mechanism the artifact writer needs (`_worktree_healthy` with stale
`index.lock` detection, `port_progress.py:366-389`; double-`--force`
removal of locked worktrees and `shutil.rmtree` fallback,
`:398-412`; idempotent `prepare()`, `:390-440`), and §2.2 folds the
two writers into one lineage so there is exactly one push channel to watch.

**Path re-rooting (driver change, OGhidra repo):** every path the driver
WRITES as tracked content resolves against the artifact worktree instead of
`repo_root`:

- `artifact_root` → `<worktree>/research/decomp/port-units`
- `staging_root` → `<worktree>/research/decomp/port-units-staging`
- `registry_path` → `<worktree>/research/decomp/generated/finish-game-port/knowledge-registry.json`
- `assembly_ledger_path` (its tracked half after the §5 split) → `<worktree>/research/decomp/data/...`

(today all four resolve against `repo_root`:
`src/port_wasm_units.py:1225-1226, 1256, 1268-1270`).

**[F3a] A fifth re-rooting v1 missed, and it fails SILENTLY:**
`registry_version_component(repo_root)`
(`src/port_wasm_units.py:614-624`) reads
`Path(repo_root) / REGISTRY_RELPATH` directly — bypassing
`self.registry_path` (`:1256`) —
and **degrades to 0 on an absent file** by design (docstring: "Absent file
=> 0, keeping the world-hash shape stable with pre-T2c verdicts"; the
`except (ValueError, OSError): return 0` at `:622-624` swallows the
missing-file case identically to a corrupt one). It feeds the
world-hash's `registry_version` component
(`src/port_wasm_units.py:709`). Post-migration the `main`-worktree copy
of the registry is deleted (§6.4), so an un-re-rooted call would pin the
component at 0 forever — every red's recorded world-hash stops seeing
registry deltas and §2.8's world-changed gating silently dies. Fix: the
function takes the worktree-resolved `registry_path`; and absence
becomes LOUD — a `registry_missing` event + page — with the silent-0
path retained ONLY for the documented pre-T2c state (registry never yet
created), distinguished by the worktree lacking the file in git
(`git cat-file` on the branch), not merely on disk.

**[F9] Worktree cost, stated:** `git worktree add` materialises the full
tracked product tree — **17,258 files** (`git ls-files | wc -l`,
2026-08-21; object store shared
with the main checkout, pack ~430 MiB, so the cost is checkout I/O and
disk for working copies, not a second clone) — and `prepare()`'s rebuild
path re-pays that checkout whenever a supervisor tree-kill wedges the
worktree (kills are the NORMAL stop path, §7 I5). Mitigation, specced as
part of §2.1: **sparse checkout**, scoped to the Class-B write surface —

```
git -C <worktree> sparse-checkout set --no-cone \
  research/decomp/port-units research/decomp/port-units-staging \
  research/decomp/generated/finish-game-port research/decomp/data \
  workflow-progress
```

— applied in `prepare()` immediately after `worktree add`. This is
sound with §2.3's merges: merge operates on the index, which always
covers the full tree, so engineering changes from `main` merge without
being materialised, and a conflict OUTSIDE the sparse cone still
surfaces in the index and triggers I6. The §6.4 restore-merge's paths
are inside the cone by construction. Everything the driver
only READS (queue files, seed header, PoC harness, oracle cwds) and
everything untracked (run_root state at `src/port_wasm_units.py:1221-1224`,
work_root scratch) stays on `repo_root` — the worktree merges `main` in (§2.3), so read paths are
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
  settled, `src/port_wasm_units.py:2658`) — never skip, because an
  artifact commit is settle-critical. The supervisor's
  `port-contract checkpoint` writer inherits the same lock unchanged.
- **[F1] The journal's unrelated-histories self-repair is SUPERSEDED —
  post-migration it is lethal.** `flush_pending_push`'s current handler
  (`port_progress.py:946-955`) responds to "unrelated histories" by
  `worktree remove --force` (`:952`) + `branch -D self.branch` (`:953`)
  + `self._prepared = False; self.prepare()` (`:954-955`), re-adopting
  the REMOTE journal. For a pure generated journal that is correct: nothing local
  is worth keeping. On the merged lineage it destroys work:
  `branch -D` discards **committed-but-unpushed artifact commits** —
  precisely the state I3's push-failure carry-forward exists to protect
  (a green whose commit landed locally but whose push failed would be
  silently un-happened, while its state record names a commit sha that
  no longer exists on any branch). Post-migration this path is REMOVED,
  not conditioned: unrelated histories on `origin/port-progress` means
  something replaced the remote branch out of band — the driver records
  pending (`port_progress_unrelated_history`), pages, and keeps
  committing locally; a human reconciles. Never auto-adopt. (§7 I12.)
- **[F2] Non-fast-forward reconcile, re-specced.** The current
  `merge -X ours --no-edit <remote>/<branch>`
  (`port_progress.py:937-939`, reached from the
  non-fast-forward/rejected branch at `:934`) auto-resolves EVERY
  conflicted path in our favour — on the merged lineage that would
  silently discard a second writer's artifact commits, and it makes
  v1's "conflicting artifact paths page" unimplementable: `-X ours`
  leaves no conflict behind to observe. Replaced: plain
  `merge --no-edit`; on conflict, resolve ONLY paths under
  `workflow-progress/` with ours (`git checkout --ours --
  workflow-progress && git add workflow-progress` — two machine
  journals racing, ours wins, as today); ANY other conflicted path ⇒
  `merge --abort`, record pending, page
  (`port_progress_foreign_writer`). Two artifact writers is a topology
  breach to surface, not a merge to win. (§7 I9.)

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
  bury the breach the conflict is reporting. (The non-fast-forward
  reconcile for the journal's OWN generated files is narrowed to
  `workflow-progress/` only — §2.2 [F2]; today's blanket `-X ours` at
  `port_progress.py:937-939` does not survive the migration.)

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

**The interim rows, for the period between now and migration.** These are
not target-topology rows; they are what is actually running, listed so the
matrix is a complete description of reality at every moment and not only
after the migration:

| # | Repo | Remote:branch | Trigger | Exact form | Lifetime |
|---|---|---|---|---|---|
| X1 | GotYaForce | `origin` : `port-staging` | every green/promotion, via `_push_product` | `git push origin HEAD:refs/heads/port-staging` (`src/port_wasm_units.py:2002-2005`) | until §6.3; **superseded by P4** |
| X2 | GotYaForce | `origin` : `port-progress` (orphan journal) | every unit transition | `git push origin port-progress:port-progress` (`port_progress.py:926`) | continuous; the branch's *meaning* changes at §6.1, the push does not |

Explicitly NOT pushes, unchanged from today's fixed code: assembly-gate
ledger commits (local, ride P4/P5/X1 — `src/port_wasm_units.py:1882-1885`),
d5-migrate registry commits (local, ride P4/P5/X1 —
`src/port_wasm_units.py:3090-3091`), and the maintenance CLIs
(`reverify --dry-run`, replay: "Never pushes",
`src/port_wasm_units.py:4149`).

**[F4] Interim reality (`ff71f52`, 2026-08-20, owner-ordered, ratified by
GotYaForce `ef6767bf`):** `_push_product`
(`src/port_wasm_units.py:1988-2006`) pushes
`origin HEAD:refs/heads/port-staging` — local lineage unchanged (`main`),
remote landing on an interim `origin/port-staging` branch,
`origin/main` receiving nothing. Two facts matter for the migration:

1. **The branch does not exist on the remote yet** (`git ls-remote origin`
   → `main`, `port-progress`, `refs/pull/1/head` only): the gate was paused
   before the first post-`ff71f52` green, so `port-staging` is created by
   the first green after the gate resumes. If the gate never resumes before
   the migration lands, `port-staging` never exists and §6.3's deletion
   step is a no-op — which is the *cheapest* outcome, not an error.
2. **Whatever it accumulates is absorbed, never merged.** `port-staging`
   only ever receives the local `main` lineage, so it is a prefix of the
   very lineage the new `port-progress` branches from (§6.1 step 3). After
   the first P4 push it is strictly redundant and is deleted
   (`git push origin :refs/heads/port-staging`, §6.3, gated on the
   `merge-base --is-ancestor` check). There is never a moment where content
   has to be moved *from* `port-staging` *to* `port-progress`.

`_push_product` is then re-specced to P4:
`git push origin port-progress:port-progress`, executed by `_git_wt` in
the artifact worktree. A push of the current branch by indirection
(`HEAD` as source) is banned in driver code even with an explicit remote —
the refspec names the branch literally, so a wrong-worktree invocation
fails loudly instead of pushing whatever was checked out (§7 G1/G2).

**[F4] Disposition of the two push sites outside the wasm-unit driver
(§1.2 item 7):**

- `port_driver.py` `_batch_push` (`src/port_driver.py:763-800`,
  `push origin HEAD`): the source-loop driver's end-of-run push. Its
  payload — LLM-generated TS integrations committed by the source loop —
  is neither review-passed engineering nor a certified promotion, so
  under R4 it has no sanctioned destination on `main`. Note it was NOT
  covered by `ff71f52`'s redirect: it is the last driver-side path that
  would still put non-engineering content on `origin/main`. The source-loop
  pipeline is not currently in service; `_batch_push` is **retired**
  (push removed; commits stay local and event-visible via the existing
  `batch_push` event, `src/port_driver.py:790-800`) and `port_driver.py`
  joins the G1/G2 guard file list — it is today in the no-console-window
  guard's file list (`tests/test_port_wasm_progress.py:417`) but in no
  push guard, and its only push coverage is the single-site
  `test_batch_push_uses_an_explicit_refspec`
  (`tests/test_port_driver.py:494-516`), whose assertion
  `pushes == [("git", "push", "origin", "HEAD")]` must be updated or
  deleted with the retirement. If the source loop returns to service, its
  integrations follow the artifact lineage (P4) until certified through
  §4 — that revival is a design change requiring its own review, not a
  matrix row reserved here.
- `incremental_port.py` (`src/incremental_port.py:427-433`,
  `push origin HEAD:refs/heads/main` from its disposable worktree): the
  legacy cumulative two-unit TS transaction — a direct, unattended
  writer to `origin/main`, i.e. an R4 violation waiting to run. It is
  **live-reachable, not merely test-reachable**: `main.py:1303-1306`
  exposes it as the CLI subcommand `prove-incremental-port`, so retiring
  it is not a matter of deleting an unused function — the entry point
  stays and only the push goes. **Retired explicitly:** the push call is
  deleted while `push_command` stays in the result record
  (`IncrementalPortResult.push_command`) so the transaction still reports
  the would-be push for a human to run by hand; the module joins the
  guard file list. Not in the matrix. (If the owner prefers, the whole
  `prove-incremental-port` subcommand can be removed instead — a
  strictly stronger form of the same disposition; the design requires
  only that no unattended path can push `main`.)

**Supersession note — three documents encode the old heartbeat and all
three must be rewritten with the migration, or the monitor pages
forever:**

1. AGENTS.md **monitoring invariant**. Already rewritten ONCE, by
   `ef6767bf`, from `main` to origin `port-staging`. It is rewritten a
   SECOND time at migration, to `origin/port-progress`. Any monitor or
   agent reading AGENTS.md between now and then correctly sees
   `port-staging`.
2. AGENTS.md **"Git traps"** bullet: "GotYaForce repo: product commits on
   `main`, machine journal on `port-progress` (worktree under
   `.tmp/port-progress-worktree`)." Post-migration `port-progress` is no
   longer *merely* a machine journal — it is the artifact lineage — and
   the bullet must say so, or the §2.0 name collision becomes a trap.
   This one is easy to miss because `ef6767bf` did not touch it.
3. The `_push_product` docstring, which currently documents the interim
   in prose (including the now-to-be-falsified sentence "the
   port-progress branch stays journal-owned ... and product history must
   never be pushed there").

The rig-side push-silence cron (ownership caveat:
compile-fix-loop-design.md §4 — the cron lives on the rig supervisor; this
repo can request, not attest) must repoint at `origin/port-progress`. It
should be checked NOW as well: if it is still watching `origin/main`, the
interim has already made it a false-alarm generator, since `origin/main`
stopped receiving greens at `ff71f52`.

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

**[F5] Prerequisite before ANY promotion can even be evaluated — the data
migration.** The preconditions below are unsatisfiable against today's
state, and the command must say so rather than silently never firing.
Measured against `wasm-units-state.json` on 2026-08-21 (1,396 units):

| Fact | Count | Consequence for §4 |
|---|---|---|
| units with ANY `verify` record | **0 of 1,396** | precondition 1's `verify.status == "pass"` is false for every unit — not merely "no passes", there is no `verify` key at all |
| greens | 27 | the whole promotion candidate pool |
| greens tiered `oracle_green` | **1** | the only unit that clears the tier half of precondition 1 |
| greens tiered `compile_only` | 24 | correctly excluded (UNVERIFIED) |
| greens with `tier: None` (pre-tier schema) | **2**, incl. `damage-core` | fail precondition 1 on the tier check even though `damage-core` has committed oracle evidence (`research/decomp/data/oracle-results/damage-core.json`) and a replay gate green |

So today `promote-to-main` would refuse all 27 greens, and for
`damage-core` it would refuse for a *misleading* reason (missing tier)
rather than the true one (schema predates the field). Therefore: a
one-time, settle-through-journal data
migration (compile-fix-loop-design.md §2.9 [V4-9]; `verdict_migrated`-class
events, exactly the 2026-08-20 migration rule) backfills `tier` and, where
provenance supports it, `verify` records from each unit's committed
provenance + journal history. Until it runs, `promote-to-main` refuses
every candidate with a distinct, non-retryable reason
(`promotion_blocked: pre_tier_schema`) so the gap reads as the known
prerequisite, not as a mysterious permanent refusal.

**Preconditions (all must hold, all machine-checkable):**

1. **Oracle-verified:** the unit's state tier is `oracle_green` with a
   `verify.status == "pass"` record from the T3 queue
   (`src/port_wasm_units.py:3468-3476`, written by `_reverify_unit_inner` on oracle pass), and the journal contains the
   corresponding `verdict_promoted` event — the settle-through-journal rule
   (compile-fix-loop-design.md §2.9 [V4-9]) applies to certification
   doubly.
2. **Assembly-gate ATTESTATION [F5]:** v1 required membership in "the most
   recent passing gate window" — unsatisfiable by construction: the
   rolling window (default N=5) means any unit older than the last five
   greens is never in it, however composable. Replaced by a
   **promotion-time attestation run**: the command itself invokes
   `run_assembly_gate_now` (`src/port_wasm_units.py:1803-1832`, docstring: "Emits NO events and takes no lock" — already
   lock-free and safe alongside a live driver) over the promotion
   candidate set ∪ the current final-build members (or `--all`), records
   the result in the gate ledger tagged `attestation` with the exact unit
   list and registry version, and the precondition consumes THAT
   attestation: pass, fresh (this command invocation, same registry
   version), covering the candidate. `last_run` and `largest_n_passed`
   are both ignored for promotion — the first is the wrong window, the
   second a high-water mark that overstates current composability
   (compile-fix-loop-design.md §2.13 advisories). No OPEN conflict record
   may implicate the unit or any symbol it defines.
3. **Part of the actual build [F5]:** the unit is named in the
   **final-build link manifest** — a Class A, owner-reviewed file. It
   **does not exist anywhere in the tree today** (verified: no
   `final-build-manifest.json`, and nothing else in
   `research/decomp/data/` plays the role — `oracle-registry.json` and
   `unit-priority.json` are selector inputs, `assembly-gate.json` is a
   composability ledger, none of them assert build membership). It is
   created, EMPTY, as part of this design's landing, at
   `research/decomp/data/final-build-manifest.json`, minimal schema:

   ```json
   {
     "manifest_schema": 1,
     "build": "gnt4-web",
     "updated_at": "<iso8601>",
     "units": [
       {"name": "<unit>", "artifact": "research/decomp/port-units/<unit>",
        "role": "<link-plan role, free text>"}
     ]
   }
   ```

   The precondition is `unit ∈ units[].name`. An empty manifest means
   nothing promotes — correct: with no defined build, "part of the
   actual build" is false of every unit, and the manifest growing is an
   owner-reviewed act (P2). A unit no build input names does not
   promote, whatever its tier.
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
`wasm-units-migration.json`, `gnt4_shim_seed.h` — precision on how these
are tracked at all [F8]: the `.gitignore` negation exception re-includes
ONLY `knowledge-registry.json` (GotYaForce `.gitignore`: the
`!.../finish-game-port/` + `!.../knowledge-registry.json` pair); the queue
files are tracked because they entered the index before, or were
force-added past, the wholesale ignore — git keeps tracking an
already-indexed file regardless of ignore rules. Any NEW Class-A file in
that directory therefore needs its own negation line or a deliberate
force-add; the policy here is a per-file negation line, so trackedness is
visible in `.gitignore` rather than an index accident. Plus
`unit-priority.json`,
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

**[F3b] `oracle-results/` — the writer and committer, specced (v1 named
the class but left the file orphaned):** the writer is the oracle harness
`research/decomp/oracle-harness/run-unit.mjs`, whose `resultsDir()`
(`run-unit.mjs:82-86`) resolves root-relative by default —
`path.join(root, "research", "decomp", "data", "oracle-results")`
(`:85`) — i.e. into the MAIN worktree, where post-migration nobody
commits it. Today those files ride whatever commit comes next, which in
practice has been reviewed engineering commits: exactly the leak [F6]
quantifies. No driver code commits `oracle-results/` at all.

Decision: **Class B, committed on the artifact lineage by the verdict
that produced the evidence.**

Mechanics — and the mechanism already exists, so this is plumbing, not a
new harness feature: `resultsDir()` already honours the env var
**`ORACLE_RESULTS_DIR`** (`run-unit.mjs:83-84`, documented in the header
usage block at `:27-29` as the override that keeps the canonical
directory from being clobbered), and it is already exercised that way by
`research/decomp/oracle-harness/tests/zero-case-guard.test.mjs:32` and by
the oracle-command sidecar's per-oracle `env` map
(`tests/test_oracle_commands_sidecar.py:97`). So: **no new parameter.**
The T3 reverify path sets `ORACLE_RESULTS_DIR` to
`<worktree>/research/decomp/data/oracle-results` when invoking the
harness, and includes the unit's result JSON in the pathspec of the SAME
`_commit_paths` commit that records the verdict — promotion commit
(`src/port_wasm_units.py:3461`) or red revocation commit (`:3367`) — so
oracle evidence and the verdict it justifies are one commit, one push
(the registry co-commit pattern, applied again). The default stays
root-relative for standalone use; owner-run standalone invocations either
point `ORACLE_RESULTS_DIR` at the worktree and commit via a small
maintenance CLI (`commit-oracle-evidence`, pathspec'd, P4 refspec) or
leave results as uncommitted scratch. Engineering commits stop carrying
oracle evidence — that is the [F6] process change.

(v1 of this section invented an `ORACLE_RESULTS_ROOT` parameter that
would have duplicated `ORACLE_RESULTS_DIR`; corrected here. Anyone
implementing §6.2 should grep for `ORACLE_RESULTS_DIR` first.)

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

*Status note:* the gate is ALREADY paused as of 2026-08-21 (owner paused it
to update the model server), which is why `origin/main` is still
`8987031e` and `origin/port-staging` does not exist. That pause is the
owner's, for an unrelated reason, and this migration does not inherit it —
6.0 still requires an explicit, verified pause of its own at execution
time. Do not assume a pause observed while reading this document is still
in effect while executing it.

*Ordering hazard, stated once:* if the gate resumes before 6.1 runs, the
driver creates `origin/port-staging` and starts accumulating there. That
is harmless (see §3 fact 2 — it is a prefix of the same lineage) and
changes nothing below except that §6.3's deletion stops being a no-op.
The genuinely dangerous resume window is between 6.1 and 6.2, covered in
6.1 step 5.

**6.1 Retire the orphan journal branch.** The name `port-progress` is
currently an orphan journal lineage (`port_progress.py:301-364`); the
target design reuses the name for the artifact lineage. Sequence:

1. Archive: `git branch port-journal-archive port-progress` and
   `git push origin port-journal-archive:port-journal-archive` — the old
   journal history stays reachable forever under a new name.
2. Remove the journal worktree
   (`git worktree remove --force .tmp/port-progress-worktree`; twice with
   `--force` if locked, the code's own trick, `port_progress.py:398-405`, with a `shutil.rmtree` fallback at `:406-412`).
3. Re-point the branch: `git branch -f port-progress <current main tip>`.
   Note this makes `port-progress` a strict superset of whatever
   `origin/port-staging` holds (both descend from `main`), which is what
   makes 6.3's deletion safe.
4. Carry the journal tree forward: check the new branch out in the
   recreated worktree, copy `workflow-progress/` from
   `port-journal-archive` into it, one commit
   (`journal: carry workflow-progress history onto the merged lineage`).
   The journal's rolling-window design (2,000-event cap,
   `port_progress.py:54-56`) means this is small by construction.
5. Replace the remote branch: `git push origin
   +refs/heads/port-progress:refs/heads/port-progress` — a one-time,
   owner-executed forced replacement of a machine journal with no
   downstream consumers. **Ordering matters, and this is the one window
   where a stray unpause is destructive:** steps 3-4 give the LOCAL
   `port-progress` a history unrelated to the remote's orphan journal, so
   until step 5 lands, the still-shipped unrelated-histories handler
   (`port_progress.py:946-955`) would fire on the next push, `branch -D`
   the freshly re-pointed local branch, and re-adopt the orphan remote —
   destroying the migration and looking like a successful self-repair
   while doing it. That handler is removed in 6.2 [F1], but 6.1 runs
   BEFORE 6.2, so during 6.1 the protection is procedural only: complete
   steps 1-5 in one uninterrupted sitting with the gate verified paused,
   and re-verify `driver_pid: null` immediately before step 5.

**6.2 Land the driver changes (OGhidra repo, review-pass, P1):** path
re-rooting (§2.1, including `registry_version_component` with loud
absence [F3a]), sparse checkout in `prepare()` [F9], `_git_wt` +
`progress.lock` around artifact commits (§2.2), removal of the
unrelated-histories auto-adopt [F1] and the narrowed non-FF reconcile
[F2], merge-forward at prepare/recycle (§2.3), `_push_product` → P4
refspec (§3), `_batch_push` and `incremental_port.py` push retirements
[F4], the assembly-gate file split (§5), the harness
`ORACLE_RESULTS_DIR` plumbing + evidence-rides-the-verdict-commit path
[F3b], the
empty final-build manifest + `promote-to-main` skeleton with the
pre-tier-schema refusal [F5], the §7 guard tests (G1 AST-level [F7]),
and all three AGENTS.md / docstring / cron supersessions (§3 — the
monitoring invariant, the "Git traps" bullet, and the `_push_product`
docstring). The `settle-unit` CLI and
`d5-migrate` re-root with the driver (their commits become `port-progress`
commits automatically — they already go through `_commit_paths`/the
registry path).

**6.3 First artifact-lineage run.** Unpause; the first unit's P4 push is
the proof: `origin/port-progress` gains a staging commit,
`origin/main` gains nothing.

**[F4] Then retire the interim branch — conditionally.** First establish
whether it exists at all: `git ls-remote origin refs/heads/port-staging`
(never a local tracking ref; AGENTS.md "Git traps": local refs lie).

- **Absent** (its state as of 2026-08-21, and its state forever if the
  gate does not resume before 6.2): nothing to do. Record the fact in the
  migration commit message so a later reader does not go hunting for a
  branch that never existed.
- **Present:** verify containment
  (`git merge-base --is-ancestor <port-staging sha> port-progress` — must
  exit 0; if it does NOT, STOP and page: something pushed to
  `port-staging` from outside the sanctioned lineage, and deleting it
  would discard commits), then delete
  (`git push origin :refs/heads/port-staging`).

Either way the end state is the same and is the checkable exit condition
for §2.0: `git ls-remote origin` shows exactly `main`,
`port-progress`, and `port-journal-archive` — one product ref, one
artifact ref, one archive — and no `port-staging`.

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

**[F8] The deletion commit vs guard G3 — the explicit exception:** this
commit touches Class-B paths on `main` by design, so an unqualified G3
monitor would page on the very commit that establishes the invariant.
The commit carries a `Migration-provenance:` trailer naming this design
doc's section (§6.4) and, once it exists, the sha of the port-progress
restore-merge; G3's exclusion list (§7) admits exactly two trailer forms
— §4's promotion provenance and this migration provenance — and the
migration form is valid for ONE commit (G3 records the first sha it
accepts and rejects any later use of the trailer, so the exception
cannot become a bypass).

**[F8] Crash-midway recovery for 6.4, documented:** the step is two
commits with a fixed order — (1) the deletion commit on `main`, P2 push;
(2) the restore-merge in the artifact worktree. A crash between them
loses nothing (both trees are still complete: `main` pre-push or
post-push, `port-progress` simply hasn't merged yet) and the half-done
state is LOUD, not lossy: if the gate is unpaused before (2) runs, the
driver's next §2.3 merge hits the deletion of artifact paths as a
conflict against the worktree's live artifact tree and refuses + pages
(I6) rather than merging the deletion through. Recovery = perform (2)
by hand exactly as written (merge with `git checkout HEAD -- <artifact
paths>` before committing), then unpause. The restore-merge is
idempotent — re-running it after a partial attempt re-resolves to the
same tree.

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
`main` is rebuilt: reset to split point `45db9ff1`, cherry-pick the
engineering commits since (**37 as of `ef6767bf`**, and the number grows
with every engineering commit that lands before the rewind — treat it as
"the non-artifact commits in `45db9ff1..main`", computed at execution
time, never as a frozen count), then
`git push --force-with-lease origin main:main`.

**[F6] They are NOT all clean cherry-picks — four leak Class B.**
v1 claimed content-disjointness; the review found, and this revision
re-verified with `git show --stat <sha> -- research/decomp/data/oracle-results`,
four engineering commits that carry `oracle-results/` evidence files
alongside their engineering content:

| Commit | Subject | Class-B payload |
|---|---|---|
| `836e0344` | `feat(decomp): oracle-harness Phase 1 …` | `oracle-results/damage-core.json` (+564) |
| `538a0783` | `fix(oracle-harness): Phase 1 review F1-F5 …` | `oracle-results/damage-core.json` (+14/−508) |
| `d7c673ba` | `oracle(p2-pilot): differential specs + generate-mode harness …` | `oracle-results/auto-c0034-018.json`, `auto-c0035-002.json` (+656) |
| `2bfe8453` | `oracle(p2-pilot): review fixes — zero-case guard …` | same two files (+12/−9) |

That is the [F3b] writer gap in action: the harness wrote root-relative
into the main worktree (`run-unit.mjs:85`) and no driver code commits
`oracle-results/`, so the files rode whatever reviewed commit came next.
Note the four are not independent — they are two edit-chains over the
same three result files, so an edited cherry-pick of an EARLIER one
changes the context the LATER one applies against; pick them in order and
expect to re-resolve.

If Option B is chosen, these four are cherry-picked **edited**: apply,
`git rm --cached` the Class-B paths, amend before continuing — so the
rebuilt `main` never contains them, at the cost of four rewritten-content
commits whose diffs no longer match their originals (in addition to the
new SHAs every rebuilt commit gets anyway).

**The implied process change, stated as a requirement rather than a
footnote:** Option B's cleanliness is not self-sustaining. The four
commits above happened because a reviewed engineering commit was allowed
to carry machine-written evidence, and nothing in review catches that by
eye. So Option B is only worth its cost if it lands together with (a) the
[F3b] `ORACLE_RESULTS_DIR` plumbing so the driver's own runs write into
the worktree, and (b) guard **G3** (§7), which is what actually makes the
recurrence loud — G3 fails any new `origin/main` commit touching a
Class-B path regardless of how respectable its subject line is. Without
(b), a clean rebuilt history starts re-contaminating at the next
standalone harness run and nobody notices for another two weeks. This
applies to Option A too — A simply never claimed retroactive
cleanliness — which is why G3 is not optional under either option.

- For: R1 holds retroactively — `main`'s history contains no artifact
  commit at all; log/blame/bisect on `main` are clean through the
  contamination window; artifact blobs eventually gc out of fresh `main`
  clones.
- Against: a force-push of the product branch — every clone and open
  branch based on post-split `main` must rebase; **all 37-and-counting
  engineering commits get new SHAs**, so every recorded citation of a post-split
  GotYaForce SHA (design docs, journal `product_commit` fields, memory
  notes) silently dangles; and the interaction with `port-progress` is
  permanent: `port-progress` branched from the OLD tip, so after the
  rewind, every §2.3 merge of new `main` re-introduces those commits as
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

**One detail that affects Option B's `--force-with-lease`:** local `main`
is currently AHEAD of `origin/main` by one unpushed engineering commit
(`ef6767bf`, the AGENTS.md interim update). `--force-with-lease` compares
against the remote-tracking ref, so this is fine as long as the tracking
ref is freshly fetched — but the general rule applies with force: verify
with `git ls-remote origin refs/heads/main` (AGENTS.md "Git traps": local
tracking refs lie), not with `git rev-parse origin/main`.

## 7. Failure modes and invariants

| # | Invariant / failure mode | Handling | Enforced by |
|---|---|---|---|
| I1 | Every push names `<remote> <refspec>` literally; no bare `git push`, no `HEAD` push in driver/journal code | design rule §3 | **guard test G1** |
| I2 | G3 heartbeat: per-unit push on `origin/port-progress`; push silence > threshold ⇒ RCA | thresholds unchanged from compile-fix-loop-design.md §4; monitored ref repointed. **Interim caveat:** until migration the heartbeat is SPLIT across `origin/port-staging` (greens, X1) and `origin/port-progress` (transitions, X2), so a monitor watching one ref alone can miss a stall class; and a monitor still watching `origin/main` has been dark since `ff71f52` | rig cron (request-not-attest caveat) + the three AGENTS.md/docstring rewrites (§3) |
| I3 | Push-failure carry-forward, exactly today's semantics: push failure ≠ commit failure; the unit settles with `pushed=False` and the NEXT branch push (P4 or P5) carries it; commit failure ⇒ unit NOT settled (`src/port_wasm_units.py:2658`); journal pending-push file + flush retries unchanged (`port_progress.py:914-960`, `src/port_wasm_units.py:3783-3788`) | preserved verbatim; the shared lineage strengthens it (any later push carries everything) | existing tests + G4 |
| I4 | Worktree lock vs driver lock: `wasm-units.lock` serializes drivers (unchanged); `progress.lock` serializes ALL writes in the shared worktree (§2.2) — driver artifact commits acquire it with bounded wait, journal keeps skip+replay | §2.2 | new unit test: concurrent checkpoint + artifact commit never interleave in one index |
| I5 | Supervisor recycle / tree-kill mid-commit leaves `index.lock` in the shared worktree | `_worktree_healthy` already detects exactly this and `prepare()` rebuilds (`port_progress.py:366-389`, the `index.lock` probe at `:378-381`) — kills are the NORMAL stop path and stay safe | existing journal tests extended to the artifact writer |
| I6 | Merge `main`→`port-progress` conflicts | refuse start + page, never auto-resolve (§2.3) | driver start path |
| I7 | Nothing merges/pushes `port-progress`→`main` except the §4 command | one writer, preconditions machine-checked | **guard test G2** + review |
| I8 | `origin/main` receives an artifact commit anyway (regression) | RCA, not waiting | **guard test G3** (monitor-side) |
| I9 | Non-fast-forward on `origin/port-progress` (second machine/worktree) | **[F2]** plain merge; ours-resolve restricted to `workflow-progress/`; any other conflicted path ⇒ abort + page (`port_progress_foreign_writer`) — never `-X ours` across the whole tree | `flush_pending_push` re-spec (§2.2 [F2]) + unit test: a synthetic remote artifact-path conflict must page, not resolve |
| I10 | Worktree deleted/corrupted mid-campaign | `prepare()` rebuilds from the branch (sparse checkout re-applied, §2.1 [F9]); committed artifacts are safe (they are commits, not worktree files); in-flight uncommitted unit artifacts are re-derived by the unit re-running (retryable, §2.10 semantics) | journal precedent |
| I11 | Settle-through-journal (compile-fix-loop-design.md §2.9) applies to every lineage operation here: promotion, certification, migration (incl. the [F5] tier/verify backfill) each emit their journal event | §4, §6 | AGENTS.md rule, review |
| I12 | **[F1]** Unrelated histories on `origin/port-progress` never auto-adopts the remote — `port_progress.py:946-955`'s `branch -D` + re-adopt path is removed at migration; the condition records pending + pages, local commits keep accumulating | §2.2 [F1] | unit test: unrelated-histories simulation must leave the local branch and its unpushed commits intact |
| I13 | Exactly one artifact ref on `origin` at rest. Three names exist across the migration (§2.0) and two of them must be gone when it ends: `port-staging` deleted (§6.3), the orphan journal preserved only as `port-journal-archive` | end-state check: `git ls-remote origin` shows `main`, `port-progress`, `port-journal-archive` and nothing else artifact-shaped | migration exit condition (§6.3) + reviewed once at completion |
| I14 | A stray gate resume during migration. Resuming between 6.0 and 6.1 is harmless (it only creates/extends `port-staging`, a prefix of the target lineage); resuming between 6.1 and 6.2 is DESTRUCTIVE (the not-yet-removed unrelated-histories handler would `branch -D` the migrated local branch and re-adopt the orphan remote) | 6.1 steps 1-5 run in one sitting, gate verified paused (`driver_pid: null`) immediately before step 5 | procedural during 6.1; enforced in code from 6.2 onward by I12 |

**Guard tests (OGhidra `tests/`, alongside the existing no-vendor-branding
guard that AGENTS.md cites as precedent):**

- **G1 — no push without explicit refspec, AST-level [F7]:** a pure
  grep cannot pass here — the sanctioned P5 push uses a VARIABLE refspec
  (`f"{self.branch}:{self.branch}"`, `port_progress.py:926`), which a
  grep for literal refspecs either rejects (false positive on sanctioned
  code) or is loosened until it checks nothing. So G1 parses the sources
  with Python's `ast` module — `src/port_wasm_units.py`,
  `src/port_progress.py`, `src/port_contract.py`,
  `src/incremental_port.py`, **`src/port_driver.py` [F4]** — finds every
  call to a git-runner whose first string argument is `"push"`, and
  asserts per call: (a) a remote argument and a refspec argument exist;
  (b) NO argument expression contains the token `HEAD` — neither as a
  string-literal substring nor as a name — banning source-by-indirection
  outright; (c) the refspec expression is either a string literal naming
  a sanctioned branch (`main:main`, or the migration's one
  `+refs/heads/port-progress:...` in migration tooling only) or an
  expression whose free variables derive from the `PROGRESS_BRANCH`
  constant / `self.branch` (the journal's f-string). Anything else —
  bare push, extra indirection, a new branch name — fails the test
  before it can run.

  **Sequencing consequence, and it is not optional:** rule (b) fails
  against the code as it stands today. Both `_push_product`'s interim
  refspec (`"HEAD:refs/heads/port-staging"`,
  `src/port_wasm_units.py:2002-2005`) and `_batch_push`'s
  `push origin HEAD` (`src/port_driver.py:786-788`) contain the token
  `HEAD`. So G1 can only be committed as part of 6.2, in the same change
  that re-specs `_push_product` to P4 and retires `_batch_push` — not
  earlier as a standalone hardening. Landing it early would either break
  the build or force a `port-staging` exemption that then has to be
  remembered and removed. Correspondingly, `test_product_push_uses_an_explicit_refspec`
  (`tests/test_port_wasm_units.py:1387`) and
  `test_batch_push_uses_an_explicit_refspec`
  (`tests/test_port_driver.py:494`) both assert the interim forms and are
  rewritten or deleted in the same change; G1 subsumes both.
- **G2 — no artifact→main writer outside promotion:** assert no git
  invocation in driver/journal code (same file list as G1) pushes to
  `main` or merges `port-progress` except inside the `promote-to-main`
  command's module scope.
- **G3 — main-cleanliness monitor (GotYaForce side, cron/CI):**
  on every new `origin/main` commit, fail if it touches a Class-B path or
  its subject matches the artifact classes
  (`^port-staging:|^port-assembly:|^port-registry:|^port: .* wasm unit `
  — note the first alternative matches the COMMIT-SUBJECT prefix
  `port-staging:`, which is unrelated to the interim BRANCH named
  `port-staging`; §2.0's name collision extends this far and the guard's
  comment must say so),
  excluding commits carrying §4 promotion provenance or the ONE
  `Migration-provenance:` commit (§6.4 [F8] — first-use-only; a second
  commit bearing the trailer fails).
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

Plus one non-requirement obligation this revision takes on: **the interim
must terminate.** `ff71f52` and `ef6767bf` bought time by moving the leak
off `origin/main`; they did not satisfy R1 (local `main` still carries
every artifact commit and the whole 168-file artifact tree), R3
(`_batch_push` still pushes `HEAD`), or R4 (no certified writer exists).
§2.0 names the three branches, §6.3 deletes the interim one, and I13 is
the checkable end-state. If this design stalls, the interim does not
decay gracefully — it just leaves a third branch name in the tree for
the next reader to misread.
