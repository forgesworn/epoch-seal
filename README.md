# epoch-seal

[![CI](https://github.com/forgesworn/epoch-seal/actions/workflows/ci.yml/badge.svg)](https://github.com/forgesworn/epoch-seal/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/epoch-seal)](https://www.npmjs.com/package/epoch-seal)
[![licence: MIT](https://img.shields.io/badge/licence-MIT-blue.svg)](./LICENCE)
[![GitHub Sponsors](https://img.shields.io/github/sponsors/TheCryptoDonkey?logo=githubsponsors&color=ea4aaa&label=Sponsor)](https://github.com/sponsors/TheCryptoDonkey)

**An old week needs three of your friends, a delay, and nobody saying no.**

A box encrypts its store per epoch. When an epoch closes, this library
splits its key across the circle and the box forgets it. From then on the
keeper can read the current epoch and nothing older, so compulsion yields
one epoch, and getting anything older back is slow, visible and needs other
people, one of whom can refuse without anyone learning who.

It composes three things that already ship: Shamir shares and the kind
30480 vault-share event from `dominion-protocol`, NIP-59 gift wraps from
`nostr-tools`, and ring-signed ballots from `nostr-anon-vote`.

## Install

```bash
npm install epoch-seal
```

epoch-seal is ESM only: `package.json` sets `"type": "module"` and `exports` has only `types` and `import` conditions, no `require`, so use `import`. There is no CommonJS build; from CommonJS, load it with `await import('epoch-seal')`. It needs Node 22 or later. The examples take key helpers from `nostr-tools`, which epoch-seal depends on at exactly 2.23.9; install that same version yourself (`npm install nostr-tools@2.23.9`) so there is one copy. The exact pin is deliberate and shared across ForgeSworn packages; [AGENTS.md](./AGENTS.md) gives the reason and says not to bump it on its own.

## The four moves

One script, run top to bottom as an ES module (it uses top-level `await`). It plays every role itself. In real use each role runs in its own process, and the mailbox is your relays and storage: epoch-seal builds and reads events and never sends one.

```ts
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { NostrEvent } from 'nostr-tools/pure'
import { sealEpoch, openShare, requestRecovery, requestDetails, refuse, recoveryOutcome, releaseShare, recoverEpoch } from 'epoch-seal'

const unixNow = () => Math.floor(Date.now() / 1000)   // every time in this library is Unix seconds
const EPOCH_ID = '2026-W37'
const DELAY_SECONDS = 48 * 3600

// Stand-in for your relays and storage.
const mailbox = new Map<string, NostrEvent[]>()
const send = (event: NostrEvent, toPubkey: string) => { mailbox.set(toPubkey, [...(mailbox.get(toPubkey) ?? []), event]) }
const received = (pubkey: string) => mailbox.get(pubkey) ?? []

// Keys. Secret keys are 32-byte Uint8Arrays; public keys are lower-case 64-character hex strings.
const keeperPrivateKey = generateSecretKey()
const memberKeys = Array.from({ length: 5 }, () => generateSecretKey())   // each member's rendezvous secret key
const members = memberKeys.map((k) => getPublicKey(k))                    // the circle: their rendezvous public keys
const epochKey = crypto.getRandomValues(new Uint8Array(32))               // stand-in for the key the closed epoch's store is encrypted under

// 1. The keeper seals a closed epoch to the circle, 3 of 5, with a 48-hour delay, and destroys the key.
const sealing = sealEpoch({ epochKey, epochId: EPOCH_ID, keeperPrivateKey, members, threshold: 3, delaySeconds: DELAY_SECONDS })
for (const s of sealing.shares) send(s.wrap, s.member)                    // one gift wrap each, nothing visible on it
const kept = { sealId: sealing.sealId, commitments: sealing.commitments } // not secret; lets recovery name a poisoned share
epochKey.fill(0)                                                          // sealEpoch does not wipe the key it is given: the caller does

// 2. Each member opens their wrap with their rendezvous secret key and keeps the share.
const shares = memberKeys.map((key) => openShare(received(getPublicKey(key))[0]!, key))

// 3. Months later the keeper asks for the epoch back, over the same circle, with a lock at least as long as the sealed delay.
const recoverySecretKey = generateSecretKey()                             // the keeper's current rendezvous key: shares come back to it. It stays local.
const request = await requestRecovery({ keeperPrivateKey, epochId: EPOCH_ID, members, delaySeconds: DELAY_SECONDS, recoverTo: getPublicKey(recoverySecretKey) })   // recoverTo is public
const firstSeen = unixNow()                                               // each member records this when the request reaches them, by their own clock

// 3a. Any member who is uneasy refuses. The ballot is ring-signed over the circle the share carries: nobody learns who.
const ballots: NostrEvent[] = []                                          // every ballot this member has received, from relays and directly
const someoneIsUneasy = false                                             // set to true and step 4 throws "recovery is refused"
if (someoneIsUneasy) {
  const ballot = await refuse(memberKeys[0]!, request, shares[0]!)
  for (const m of shares[0]!.members) send(ballot, m)                     // as well as the relay: a relay the keeper picks can drop it
  ballots.push(ballot)
}

// 4. After the lock, with no refusal, members release; three shares rebuild the key.
const graceSeconds = 3600                                                 // your own policy: epoch-seal sets no grace period and does not enforce one
const releaseAt = firstSeen + DELAY_SECONDS + graceSeconds                // simulated clock; in real use omit `now` and call this later
console.log(recoveryOutcome(request, ballots, members, releaseAt))        // 'allowed' ('refused' if anyone refused)
const { recoverTo } = requestDetails(request)
for (const i of [0, 1, 2]) {
  send(releaseShare({ memberPrivateKey: memberKeys[i]!, share: shares[i]!, request, ballots, firstSeen, now: releaseAt }), recoverTo)
}
const key = recoverEpoch(received(recoverTo).map((wrap) => openShare(wrap, recoverySecretKey)), { expected: kept })   // the 32 bytes epochKey held before it was wiped
```

## Values and types

| Name | Type | Notes |
|------|------|-------|
| `epochKey` | `Uint8Array` | Exactly 32 bytes; `sealEpoch` throws otherwise. `sealEpoch` neither wipes nor keeps it: `epochKey.fill(0)` zeroes only that array, so remove any other copy yourself. `recoverEpoch` returns a 32-byte `Uint8Array`. |
| `keeperPrivateKey`, `memberPrivateKey` | `Uint8Array` | A 32-byte Nostr secret key, as `generateSecretKey()` returns it. Not hex. |
| `members`, `recoverTo` | `string` | A public key: lower-case 64-character hex, x-only. Upper case and `npub` are rejected. `members` is de-duplicated and sorted for you, needs at least two distinct entries, and `sealEpoch` rejects a circle that contains the keeper. |
| `threshold` | `number` | An integer from 2 to the number of members. |
| `epochId` | `string` | Non-empty, no colon. |
| `delaySeconds` | `number` | An integer, at least `MIN_DELAY_SECONDS` (3600). |
| `firstSeen`, `now`, `opens`, `closes` | `number` | Unix time in whole seconds. Never milliseconds, never a `Date`. `now` is a function returning seconds (`() => number`) in `sealEpoch`, `requestRecovery` and `refuse`, and a plain number in `releaseShare` and `recoveryOutcome`. |
| `wrap`, `request`, `ballot` | `NostrEvent` | The event type from `nostr-tools/pure`. |
| `expected` | `{ sealId: string; commitments: string[] }` | What the keeper kept at sealing: `sealing.sealId` and `sealing.commitments`. `commitments[i]` is the commitment for share index `i + 1`, so store the array in the order `sealEpoch` returned it. Optional: without it, `recoverEpoch` judges the shares against the commitment set a majority of them carry. |

### Which key is which

- **Rendezvous key**: the Nostr key pair a party receives gift wraps at. The `members` list is the members' rendezvous public keys, and each member's rendezvous secret key is what they pass as `memberPrivateKey` to `openShare`, `refuse` and `releaseShare`.
- **Keeper key**: `keeperPrivateKey` signs the shares and the recovery request. It may not be any member's key.
- **Recovery key** (`recoverySecretKey` above, the keeper's current rendezvous key): the key the returned shares are wrapped to. Its **public** half goes into `recoverTo`, which the request publishes in plain text for every member and relay to read. Its **secret** half goes only into `openShare` on the keeper's own machine, to open the returned wraps, and never into a request, a ballot or any other event. `requestRecovery` cannot tell a secret from a public key: a 64-character hex secret key passes its format check and would be published. Always pass `getPublicKey(secretKey)`.

### Time limits

- **The lock** is `delaySeconds` on the request: it opens one second before it was made and closes `delaySeconds` after. Both `sealEpoch` and `requestRecovery` refuse anything under `MIN_DELAY_SECONDS` (3600 seconds, the one-hour floor), and a share refuses a request whose lock is shorter than the delay it was sealed with.
- **The member's delay** is that sealed delay, counted from `firstSeen`, the member's own record of when the request first reached them. `releaseShare` throws until `firstSeen + share.delaySeconds`, and also until the request's lock has closed.
- **The grace period** is a wait the client adds after the member's own delay has ended (after `firstSeen + share.delaySeconds`), so that a refusal cast at the last moment has time to arrive. epoch-seal defines no value and no constant for it, and `releaseShare` does not check it: it is the client's policy, and should be longer than the slowest path a refusal might take, by relay or directly.
- **The release window** is `RELEASE_WINDOW_SECONDS` (seven days, 604800 seconds), counted from the request's close (`closes`). From the close until the end of the window, with no refusal, `recoveryOutcome` returns `'allowed'`; after it, `'expired'`, and `releaseShare` throws.

## What it gives

- **Compulsion yields one epoch.** The keeper cannot produce an older key alone, because it does not exist anywhere alone.
- **Recovery is witnessed.** A request is an election every member sees. Silence until the lock passes is consent.
- **Refusal is anonymous.** A ballot is ring-signed over the circle. The keeper, and whoever is standing over the keeper, cannot tell which friend said no.
- **The circle and the delay are fixed at sealing.** Every share carries the circle itself, its hash and the shortest lock a recovery may have. A request over any other circle, or with a shorter lock, releases nothing, so a keeper under pressure cannot ask a circle of their own choosing, ask quickly, or choose who is able to refuse by choosing who is told the list.
- **The delay is the member's.** Each member measures it from the moment they first saw the request, by their own clock, and a request whose lock had already closed when they first saw it releases nothing. A request dated into the past neither shortens the wait nor removes the refusal: `refuse` casts at any time, whatever the request's dates say.
- **A poisoned share is named.** Every share carries a commitment to every share of its sealing and to the key. A returned share that does not match the set the keeper kept, or the set a majority of returned shares carry, is refused by index (`PoisonedShareError`, whose `index` property is the share index, which the keeper can map to the member who returned it); a tie blames nobody (`ShareSetError`, whose `indices` property lists the shares that disagree with the first). A reconstruction that does not match the key commitment is an error, never a wrong key.
- **A refusal is a refusal whenever it was cast.** A valid ring signature over the circle bound to the request's election id counts, even if its timestamp is after close and even against a re-signed copy of the request. It can still come too late: once the first member has released, that share is gone, so the deadline that matters is the earliest member's delay, and clients should wait a grace period past their own (see Time limits).
- **The ballot names nobody.** The share wraps name the members' rendezvous keys, as every gift wrap names its recipient, and the request names the keeper and the destination. Only the refusal is anonymous, and only at the event layer: a member's relay connection is their own business.

## What it does not do

- **Decoys, duress phrases, silent alarms.** Those are CAIRN's coercion-resistant layer and stay behind its implementation gate. This is honest threshold recovery: a refusal is visible as a refusal, and a coerced keeper is a keeper who has to wait 48 hours in front of someone.
- **Choose the threshold or the delay for you.** Both are the keeper's at sealing time, and the profile that uses this says what they should be. The floor is an hour: `MIN_DELAY_SECONDS`, 3600 seconds.
- **Stop the keeper's own circle from helping a coerced keeper.** If enough members release, the epoch comes back. The circle is the defence.
- **Deliver the refusal.** Silence is consent, so a relay that drops ballots turns a refusal into consent, and the keeper often chooses the relay. A refusing member sends the ballot to every other member directly as well (the share carries the list), and every member waits a grace period past their delay before releasing (see Time limits; the library sets no value).
- **Talk to relays.** It builds and reads events.

## Security notes

- `openShare` opens the gift wrap by hand and verifies the seal's signature and that the rumor's author is the sealer. `nostr-tools`' `unwrapEvent` verifies nothing and is not used.
- `requestDetails` verifies the request's signature and refuses anything that is not exactly the shape `requestRecovery` makes: two options, one tally key equal to the author, a committed ring, a lock later than its open.
- `releaseShare` throws unless the request is the sealing keeper's, for this epoch, over the sealed circle, with a lock no shorter than the sealed delay, first seen before it closed and no later than now, that delay has passed since this member first saw it, the lock has closed with no refusal, and the release window (`RELEASE_WINDOW_SECONDS`, seven days from the request's close) is still open. A client must not catch that and release anyway.
- A member judges the outcome with `isRefusal` alone; the tally key is never needed, because any valid ballot is a refusal, an `allow` ballot included.
- `refuse` builds the ballot itself from `@forgesworn/ring-sig` and nostr-anon-vote's primitives rather than `castBallot`, which refuses to cast once the wall clock passes the request's close.
- `recoverEpoch` needs `threshold` distinct shares from one sealing that all carry the same commitment set and each match their commitment. Shares from two sealings never mix.
- The keeper may not be a member of its own circle, and the epoch id may not contain a colon.

## What remains

In the profile's own words, from its table of what can be compelled: a
compelled person yields the current epoch, and no more. A box can be
seized; sealed parcels are bytes without the circle's keys; the keeper's
own tier is the keeper's. And the circle is the defence: a keeper whose
friends will release under pressure has no protection this library can
add.

## Licence

MIT. ForgeSworn.
