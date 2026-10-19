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
src/index.ts     - public exports
src/seal.ts      - sealEpoch, openShare, recoverEpoch, commitments
src/recovery.ts  - requestRecovery, refuse, releaseShare, recoveryOutcome
test/            - test suite
```

## Conventions

- British English in prose and comments.
- No third-party relay I/O: the library only builds and reads Nostr events.
- Node >=22.
- ESM only: `"type": "module"`, and `exports` offers only `types` and `import`. Use `import`; there is no CommonJS build (from CommonJS, `await import('epoch-seal')`).

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
