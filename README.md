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

// 1. The keeper seals a closed epoch to the circle, 3 of 5, and destroys the key.
const shares = sealEpoch({ epochKey, epochId: '2026-W37', keeperPrivateKey, members, threshold: 3 })
for (const s of shares) send(s.wrap, s.member)      // one gift wrap each, nothing visible on it

// 2. Each member opens theirs and keeps it.
const mine = openShare(wrap, myRendezvousKey)

// 3. Months later the keeper asks for the epoch back, with a time lock.
const request = await requestRecovery({ keeperPrivateKey, epochId: '2026-W37', members, delaySeconds: 48 * 3600, recoverTo: myCurrentKey })

// 3a. Any member who is uneasy refuses. The ballot is ring-signed over the circle: nobody learns who.
const ballot = await refuse(myRendezvousKey, request, members)

// 4. After the lock, with no refusal, members release; three shares rebuild the key.
if (recoveryOutcome(request, ballots, members) === 'allowed') send(releaseShare({ memberPrivateKey, share: mine, request, ballots, members }))
const key = recoverEpoch(returnedShares.map((w) => openShare(w, myCurrentKey)))
```

## What it gives

- **Compulsion yields one epoch.** The keeper cannot produce an older key alone, because it does not exist anywhere alone.
- **Recovery is witnessed.** A request is an election every member sees. Silence until the lock passes is consent.
- **Refusal is anonymous.** A ballot is ring-signed over the circle. The keeper, and whoever is standing over the keeper, cannot tell which friend said no.
- **Nothing on the wire names anyone.** Shares travel as gift wraps; the request and ballots are the anonymous-vote kinds.

## What it does not do

- **Decoys, duress phrases, silent alarms.** Those are CAIRN's coercion-resistant layer and stay behind its implementation gate. This is honest threshold recovery: a refusal is visible as a refusal, and a coerced keeper is a keeper who has to wait 48 hours in front of someone.
- **Choose the delay or the threshold.** Both are the keeper's, and the profile that uses this says what they should be.
- **Talk to relays.** It builds and reads events.

## Security notes

- `releaseShare` throws unless the outcome is `allowed`. A client must not catch that and release anyway.
- A member judges the outcome with `verifyBallot` alone; the tally key is never needed, because any valid ballot is a refusal.
- `recoverEpoch` needs exactly `threshold` distinct shares from one sealing. Shares from two sealings never mix.
- `createElection` and `castBallot` check the wall clock: a refusal must be cast while the request is open.

## Licence

MIT. ForgeSworn.
