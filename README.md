# epoch-seal

**An old week needs three of your friends, a delay, and nobody saying no.**

A box encrypts its store per epoch. When an epoch closes, this library
splits its key across the circle and the box forgets it. From then on the
keeper can read the current epoch and nothing older, so compulsion yields
one epoch, and getting anything older back is slow, visible and needs other
people, one of whom can refuse without anyone learning who.

It composes three things that already ship: Shamir shares and the kind
30480 vault-share event from `dominion-protocol`, NIP-59 gift wraps from
`nostr-tools`, and ring-signed ballots from `nostr-anon-vote`.

## The four moves

```ts
import { sealEpoch, openShare, requestRecovery, refuse, recoveryOutcome, releaseShare, recoverEpoch } from 'epoch-seal'

// 1. The keeper seals a closed epoch to the circle, 3 of 5, with a 48-hour delay, and destroys the key.
const sealing = sealEpoch({ epochKey, epochId: '2026-W37', keeperPrivateKey, members, threshold: 3, delaySeconds: 48 * 3600 })
for (const s of sealing.shares) send(s.wrap, s.member)   // one gift wrap each, nothing visible on it
keep(sealing.sealId, sealing.commitments)                 // not secret; lets recovery name a poisoned share

// 2. Each member opens theirs and keeps it.
const mine = openShare(wrap, myRendezvousKey)

// 3. Months later the keeper asks for the epoch back, over the same circle, with a lock at least as long as the sealed delay.
const request = await requestRecovery({ keeperPrivateKey, epochId: '2026-W37', members, delaySeconds: 48 * 3600, recoverTo: myCurrentKey })

// 3a. Any member who is uneasy refuses. The ballot is ring-signed over the circle: nobody learns who.
const ballot = await refuse(myRendezvousKey, request, members)

// 4. After the lock, with no refusal, members release; three shares rebuild the key.
const firstSeen = whenIFirstSawIt(request)                // the member's own clock, never the request's dates
send(releaseShare({ memberPrivateKey, share: mine, request, ballots, members, firstSeen }))
const key = recoverEpoch(returnedShares.map((w) => openShare(w, myCurrentKey)), { expected: kept })
```

## What it gives

- **Compulsion yields one epoch.** The keeper cannot produce an older key alone, because it does not exist anywhere alone.
- **Recovery is witnessed.** A request is an election every member sees. Silence until the lock passes is consent.
- **Refusal is anonymous.** A ballot is ring-signed over the circle. The keeper, and whoever is standing over the keeper, cannot tell which friend said no.
- **The circle and the delay are fixed at sealing.** Every share carries a hash of the circle and the shortest lock a recovery may have. A request over any other circle, or with a shorter lock, releases nothing, so a keeper under pressure cannot ask a circle of their own choosing or ask quickly.
- **The delay is the member's.** Each member measures it from the moment they first saw the request, by their own clock. A request dated into the past does not shorten it.
- **A poisoned share is named.** Every share carries a commitment to every share of its sealing. A returned share that does not match is refused by index, which the keeper can map to the member who returned it.
- **A refusal is a refusal whenever it was cast.** A valid ring signature over the circle bound to the request counts, even if its timestamp is after close, so a late objection is never discarded by a clock.
- **Nothing on the wire names anyone.** Shares travel as gift wraps; the request and ballots are the anonymous-vote kinds. The sealing id and commitments are inside the wrap, and reveal nothing about the key.

## What it does not do

- **Decoys, duress phrases, silent alarms.** Those are CAIRN's coercion-resistant layer and stay behind its implementation gate. This is honest threshold recovery: a refusal is visible as a refusal, and a coerced keeper is a keeper who has to wait 48 hours in front of someone.
- **Choose the threshold or the delay for you.** Both are the keeper's at sealing time, and the profile that uses this says what they should be. The floor is an hour.
- **Stop the keeper's own circle from helping a coerced keeper.** If enough members release, the epoch comes back. The circle is the defence.
- **Talk to relays.** It builds and reads events.

## Security notes

- `openShare` opens the gift wrap by hand and verifies the seal's signature and that the rumor's author is the sealer. `nostr-tools`' `unwrapEvent` verifies nothing and is not used.
- `requestDetails` verifies the request's signature and refuses anything that is not exactly the shape `requestRecovery` makes: two options, one tally key equal to the author, a committed ring, a lock later than its open.
- `releaseShare` throws unless the request is the sealing keeper's, for this epoch, over the sealed circle, with a lock no shorter than the sealed delay, that delay has passed since this member first saw it, the lock has closed with no refusal, and the seven-day release window is still open. A client must not catch that and release anyway.
- A member judges the outcome with `isRefusal` alone; the tally key is never needed, because any valid ballot is a refusal.
- `recoverEpoch` needs `threshold` distinct shares from one sealing that all carry the same commitment set and each match their commitment. Shares from two sealings never mix.
- `castBallot` checks the wall clock, so a refusal is normally cast while the request is open; a late one still counts on the reading side.
- The keeper may not be a member of its own circle, and the epoch id may not contain a colon.

## Licence

MIT. ForgeSworn.
