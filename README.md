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

// 3a. Any member who is uneasy refuses. The ballot is ring-signed over the circle the share carries: nobody learns who.
const ballot = await refuse(myRendezvousKey, request, mine)
sendToEveryMember(ballot, mine.members)                   // as well as the relay: a relay the keeper picks can drop it

// 4. After the lock, with no refusal, members release; three shares rebuild the key.
const firstSeen = whenIFirstSawIt(request)                // the member's own clock, never the request's dates
send(releaseShare({ memberPrivateKey, share: mine, request, ballots, firstSeen }))   // after a grace period past the delay
const key = recoverEpoch(returnedShares.map((w) => openShare(w, myCurrentKey)), { expected: kept })
```

## What it gives

- **Compulsion yields one epoch.** The keeper cannot produce an older key alone, because it does not exist anywhere alone.
- **Recovery is witnessed.** A request is an election every member sees. Silence until the lock passes is consent.
- **Refusal is anonymous.** A ballot is ring-signed over the circle. The keeper, and whoever is standing over the keeper, cannot tell which friend said no.
- **The circle and the delay are fixed at sealing.** Every share carries the circle itself, its hash and the shortest lock a recovery may have. A request over any other circle, or with a shorter lock, releases nothing, so a keeper under pressure cannot ask a circle of their own choosing, ask quickly, or choose who is able to refuse by choosing who is told the list.
- **The delay is the member's.** Each member measures it from the moment they first saw the request, by their own clock, and a request whose lock had already closed when they first saw it releases nothing. A request dated into the past neither shortens the wait nor removes the refusal: `refuse` casts at any time, whatever the request's dates say.
- **A poisoned share is named.** Every share carries a commitment to every share of its sealing and to the key. A returned share that does not match the set the keeper kept, or the set a majority of returned shares carry, is refused by index, which the keeper can map to the member who returned it; a tie blames nobody. A reconstruction that does not match the key commitment is an error, never a wrong key.
- **A refusal is a refusal whenever it was cast.** A valid ring signature over the circle bound to the request's election id counts, even if its timestamp is after close and even against a re-signed copy of the request. It can still come too late: once the first member has released, that share is gone, so the deadline that matters is the earliest member's delay, and clients should wait a grace period past their own.
- **The ballot names nobody.** The share wraps name the members' rendezvous keys, as every gift wrap names its recipient, and the request names the keeper and the destination. Only the refusal is anonymous, and only at the event layer: a member's relay connection is their own business.

## What it does not do

- **Decoys, duress phrases, silent alarms.** Those are CAIRN's coercion-resistant layer and stay behind its implementation gate. This is honest threshold recovery: a refusal is visible as a refusal, and a coerced keeper is a keeper who has to wait 48 hours in front of someone.
- **Choose the threshold or the delay for you.** Both are the keeper's at sealing time, and the profile that uses this says what they should be. The floor is an hour.
- **Stop the keeper's own circle from helping a coerced keeper.** If enough members release, the epoch comes back. The circle is the defence.
- **Deliver the refusal.** Silence is consent, so a relay that drops ballots turns a refusal into consent, and the keeper often chooses the relay. A refusing member sends the ballot to every other member directly as well (the share carries the list), and every member waits a grace period past their delay before releasing.
- **Talk to relays.** It builds and reads events.

## Security notes

- `openShare` opens the gift wrap by hand and verifies the seal's signature and that the rumor's author is the sealer. `nostr-tools`' `unwrapEvent` verifies nothing and is not used.
- `requestDetails` verifies the request's signature and refuses anything that is not exactly the shape `requestRecovery` makes: two options, one tally key equal to the author, a committed ring, a lock later than its open.
- `releaseShare` throws unless the request is the sealing keeper's, for this epoch, over the sealed circle, with a lock no shorter than the sealed delay, first seen before it closed and no later than now, that delay has passed since this member first saw it, the lock has closed with no refusal, and the seven-day release window is still open. A client must not catch that and release anyway.
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
