# epoch-seal

A TypeScript library that seals an epoch key to a fixed circle: threshold
Shamir shares gift-wrapped to members, and a time-locked, witnessed
recovery request any member can refuse by anonymous ring-signed ballot. It
builds and reads Nostr events; it does not talk to relays itself.

## Build & Test

| Command | Purpose |
|---------|---------|
| `npm ci` | Install dependencies |
| `npm run build` | Compile to `dist/` |
| `npm test` | Run the test suite (vitest) |
| `npm run typecheck` | Type-check without emitting |

## Structure

```
src/index.ts     - public exports (re-exports from seal.ts and recovery.ts)
src/seal.ts      - sealEpoch, openShare, recoverEpoch; the commitments
                   (canonicalCircle, circleHash, shareCommitment, keyCommitment);
                   SEALED_TIER, MIN_DELAY_SECONDS; the errors PoisonedShareError
                   and ShareSetError; SealOptions, SealedShare, Sealing,
                   OpenedShare, RecoverOptions
src/recovery.ts  - requestRecovery, refuse, requestDetails, isRefusal,
                   recoveryOutcome, releaseShare; REFUSE, ALLOW,
                   RELEASE_WINDOW_SECONDS; RecoveryRequestOptions, RefuseOptions,
                   RequestDetails, ReleaseOptions, Outcome
test/            - test suite
```

## Conventions

- British English in prose and comments.
- No third-party relay I/O: the library only builds and reads Nostr events.
- Node >=22.
- ESM only: `"type": "module"`, and `exports` offers only `types` and `import`. Use `import`; there is no CommonJS build (from CommonJS, `await import('epoch-seal')`).

## The nostr-tools pin

`nostr-tools` is pinned to exactly `2.23.9` in `dependencies`, with a matching
root `overrides` entry. Do not bump it, turn it into a range or remove the
override as a side effect of other work.

- Why: ForgeSworn packages used together pin the same version, so one copy of
  `nostr-tools` is installed. 2.23.9 was kept while upstream issue
  https://github.com/nbd-wtf/nostr-tools/issues/539 was open: from 2.23.11, a
  pool with `enablePing` closes its relay connection and live subscriptions
  die after about 70 seconds.
- epoch-seal opens no pools itself (it imports only `nostr-tools/pure`,
  `nostr-tools/nip44` and `nostr-tools/nip59`), so that bug does not touch this
  library directly. The pin is for consistency with the packages it runs
  alongside.
- `overrides` only takes effect when this repository is the root of an install
  (development and tests). It does not bind consumers, which is why the README
  tells them to install the same version themselves.
- Upstream status, checked on 2026-10-19: #539 was closed on 2026-07-29 and its
  fix commit first ships in 2.24.2. The pin has not been lifted. Lifting it is
  a decision for the owner, taken across all ForgeSworn packages together, not
  a change to make in this repository alone.

## Common Pitfalls

- `nostr-tools`' `unwrapEvent` verifies nothing; `openShare` does its own
  signature and author checks. Do not swap it in.
- `refuse` builds ballots from `@forgesworn/ring-sig` and nostr-anon-vote's
  primitives directly, not `castBallot`, because `castBallot` refuses to
  cast once the wall clock passes the request's close.
- `releaseShare` throws unless every one of its documented conditions
  holds (see README "Security notes"); do not catch and release anyway.
- The keeper may not be a member of its own circle; the epoch id may not
  contain a colon.
- `sealEpoch` does not wipe `epochKey`; the caller does (`epochKey.fill(0)`).
- `recoverTo` is published in plain text in the request: pass a public key
  (`getPublicKey(secretKey)`), never a secret key. A 64-hex secret passes
  the format check. The matching secret key goes only to `openShare`.
- Keys are 32-byte `Uint8Array` secrets; `members` and `recoverTo` are
  lower-case 64-hex public keys; times are Unix seconds.
