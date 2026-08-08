# Goal 3 isolation

- Source repository: `/Users/kushida/Documents/rust-and-iphone`
- Goal 3 repository: `/Users/kushida/Documents/rust-and-iphone-goal3-macless-iphone`
- Mode: A — Git worktree
- Branch: `goal3/macless-iphone-builds`
- Stable base: `d6887eba95b8116799801118c5026210628397f9`

The source checkout is read-only for Goal 3. The only source-side mutation was the explicitly permitted `git worktree add`, which created this sibling checkout and its branch. All builds, tests, generated output, caches, and later mutations run in the Goal 3 checkout through `scripts/goal3-run` where practical.

The wrapper rejects execution when its canonical current directory is inside the source repository and rejects direct absolute arguments targeting that repository. It exports isolated target, cache, config, artifact, and temporary roots, creates an operation ID, and records only command/path categories—not command arguments or secret material. A negative test from the source checkout exited 64 before running `/usr/bin/true`.

The wrapper is defense in depth, not an operating-system write sandbox: opaque child behavior and encoded shell scripts cannot be proven safe by argument inspection. Goal 3 therefore also relies on the physical sibling checkout, narrow commands, explicit target paths, and the invariant that no Goal 3 command receives a source path.

Direct bootstrap mutations before the wrapper became available are recorded in `GOAL3_COMMAND_AUDIT.jsonl`.
