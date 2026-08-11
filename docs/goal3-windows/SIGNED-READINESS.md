# Signed readiness

Signed readiness is a policy and configuration check. It is not a signed build, and a signed build is not physical-device validation.

## Current implementation foundation

The current tree contains protected-environment policy, private execution-repository checks, manual signing setup, bounded application/extension profile mapping, secret-name derivation, split compile/signing phases, signing-report transport, and synthetic validation tests. Signing bytes remain outside project source and durable job/log output.

The frozen metadata-only inspection/setup commands are:

```powershell
cargo ferry signing doctor --remote github --project-dir <project>
cargo ferry --json signing doctor --remote github --project-dir <project>
cargo ferry signing setup manual --help
cargo ferry signing teams --project-dir <project>
```

Ready exits 0. A complete non-ready inspection returns `github_signing_not_ready`, exit 4, with structured `data.ready` and `data.checks`; usage errors exit 2. Checks cover stable public/private repository identities, Actions policy, trigger-appropriate workflow registration, protected Environment metadata, Team/target/profile mapping, temporary-ref namespace, and Phase A/Phase B isolation. GitHub secret APIs are used for names/metadata only, never values.

The GitHub credential needs repository Administration-read permission for Actions policy and Actions-read permission for workflow metadata. Environment-secret inspection lists names/metadata only; missing API permission is a readiness failure, not evidence that policy or assets are absent.

When the implementation checks pass but assets are absent, human output states:

```text
Signed Phase B implementation is ready,
but real Apple signing assets are not configured.

Required:
  Apple Development PKCS#12
  PKCS#12 password
  development provisioning profile
  registered device
  private execution repository
  protected Environment
```

This block is readiness guidance, not proof that any asset exists or is correct.

## Readiness checklist

- [ ] Exact source and private execution repositories recorded by stable repository identity.
- [ ] Trusted worker revision and workflow bytes match the reviewed source.
- [ ] Protected signing environment exists and cannot run unreviewed public-fork code.
- [ ] Required reviewers/branch policy are configured for the protected environment.
- [ ] Only the expected derived secret names exist; secret values are never read into evidence.
- [ ] Real Apple Development certificate/private key and provisioning profiles are user-owned and current.
- [ ] Team, application identifier, extensions, entitlements, selected device, and profile device lists agree.
- [ ] Registered physical device is available for install/launch validation.
- [ ] Phase A has no signing-secret access; Phase B alone can access protected assets.
- [ ] Signed outputs include independently validated signing and cleanup reports.

## External blockers

Real signed acceptance requires user authorization and assets: certificate/private key, password if applicable, bounded provisioning profiles, Team ID, registered device identifier, protected environment, and a private trusted execution repository. These must not be fabricated, copied into docs, or inferred from configuration names.

## Evidence state

| Level | State |
| --- | --- |
| Implemented | Metadata-only signing doctor plus signing-policy and transport checks are implemented. |
| Locally tested | GitHub provider 316 passed/1 explicit live ignored; focused doctor tests and strict provider Clippy pass. |
| Windows-native tested | CLI parsing/rendering and integrated binary suites pass; no configured readiness success is claimed. |
| GitHub live validated | Historical unsigned Linux-originated runs exist elsewhere; no Windows-originated signed readiness run is evidence here. |
| Apple signed validated | Not validated. |
| Physical-device validated | Not validated. |
