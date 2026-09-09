# Changelog

## 0.2.0 (2026-09-09)

### Features

- seal an epoch key to a circle and recover it by witnessed, refusable, time-locked request

### Bug Fixes

- second review pass on sealing and recovery
- apply the independent review to sealing and recovery



## 0.1.0

- Second review pass (2026-09-09): `refuse` casts at any time (built from
  ring-sig primitives, no wall-clock gate), so a backdated request has
  refusers; shares carry the circle itself and a key commitment;
  `releaseShare` refuses a request first seen after it closed or a
  `firstSeen` in the future; a refusal counts against a re-signed copy of
  the same election id; recovery names a poisoned share against the
  majority set and never returns a key that fails its commitment.

- sealEpoch, openShare, recoverEpoch over dominion shares and NIP-59.
- requestRecovery, refuse, recoveryOutcome, releaseShare over nostr-anon-vote.
