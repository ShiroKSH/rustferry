# Goal 3 Windows status

Captured `2026-08-09` on the physical Windows host.

| Milestone | State | Evidence |
| --- | --- | --- |
| 0 — handoff and baseline | Complete | Handoff fetched at `5363942`; required ancestry passed; Windows branch and isolated directories created; metadata/fmt/diff baseline passed |
| 1 — Windows native regression | Pending | No package or workspace test result yet |
| 2 — live Windows acceptance | Pending | No Windows-originated GitHub/macOS run yet |
| 3 — persistent jobs | Pending | Existing implementation not yet audited against the Windows handoff specification |
| 4 — cancel/retry | Pending | No live cancellation or exact-source retry evidence |
| 5 — artifact CLI | Pending | Existing artifact validation not yet audited against the requested management UX |
| 6 — GitHub snapshot | Pending | Existing deterministic bundles are implemented; GitHub dirty-tree snapshot flow not yet validated |
| 7 — signed readiness | Pending | No private execution repository/environment readiness result yet |
| 8 — signed/device acceptance | Blocked on assets, not attempted | No user-owned Apple certificate/profile/registered device supplied |
| 9 — VS Code adapter | Pending | Existing extension retained; new jobs/snapshot UX not yet audited |
| 10 — landing | Pending | No PR/merge; Goal 3 `dist/` packages remain tracked |

Validation vocabulary remains strict: implemented, locally tested, Windows-native tested, GitHub live validated, Apple signed validated, and physical-device validated are separate claims.
