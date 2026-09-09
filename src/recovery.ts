import { bytesToHex } from '@noble/hashes/utils.js'
import { getPublicKey } from 'nostr-tools/pure'
import { wrapEvent } from 'nostr-tools/nip59'
import type { NostrEvent } from 'nostr-tools/pure'
import { castBallot, createElection, parseElection, verifyBallot } from 'nostr-anon-vote'
import { buildVaultShareEvent } from 'dominion-protocol/nostr'
import { SEALED_TIER, type OpenedShare } from './seal.js'

export const REFUSE = 'refuse'
export const ALLOW = 'allow'

export interface RecoveryRequestOptions {
  keeperPrivateKey: Uint8Array
  epochId: string
  /** The circle's rendezvous pubkeys, exactly the set the epoch was sealed to. */
  members: string[]
  /** The time lock: seconds from now before shares may be released. */
  delaySeconds: number
  /** Where the shares should come back to. Usually the keeper's current rendezvous key. */
  recoverTo: string
  now?: () => number
}

/**
 * Ask the circle for an old epoch back. The request is an anonymous-vote
 * election whose only meaningful ballot is a refusal: a member who is
 * uneasy casts one, ring-signed over the circle, and nobody, the keeper
 * included, learns which member it was. Consent is silence until the time
 * lock passes.
 */
export async function requestRecovery(opts: RecoveryRequestOptions): Promise<NostrEvent> {
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000)
  if (opts.delaySeconds < 1) throw new Error('a recovery needs a time lock')
  const keeperPub = getPublicKey(opts.keeperPrivateKey)
  const ring = [...new Set(opts.members)]
  return createElection(bytesToHex(opts.keeperPrivateKey), {
    electionId: `unseal:${opts.epochId}:${now}`,
    title: `Unseal epoch ${opts.epochId}`,
    description: `Shares to ${opts.recoverTo}. A ballot is a refusal. Silence until close is consent.`,
    options: [REFUSE, ALLOW],
    scale: 'community',
    eligibleEntityTypes: ['member'],
    eligibleMinTier: 1,
    opens: now - 1,
    closes: now + opts.delaySeconds,
    reVote: 'denied',
    tallyPubkeys: [keeperPub],
    eligibleRing: ring,
  })
}

/** A member refuses. The ballot names no one. */
export async function refuse(memberPrivateKey: Uint8Array, request: NostrEvent, members: string[]): Promise<NostrEvent> {
  const { event } = await castBallot(bytesToHex(memberPrivateKey), request, REFUSE, [...new Set(members)])
  return event
}

export type Outcome = 'pending' | 'refused' | 'allowed'

/**
 * What the circle has decided. Any valid ballot is a refusal, whatever it
 * says inside, so members can judge the outcome without the tally key.
 */
export function recoveryOutcome(request: NostrEvent, ballots: NostrEvent[], members: string[], now = Math.floor(Date.now() / 1000)): Outcome {
  const parsed = parseElection(request)
  if (!parsed) throw new Error('not a recovery request')
  const ring = [...new Set(members)]
  if (ballots.some((b) => verifyBallot(b, request, ring).valid)) return 'refused'
  return now >= parsed.closes ? 'allowed' : 'pending'
}

/** The epoch a request is for, and where the shares should go. */
export function requestDetails(request: NostrEvent): { epochId: string; recoverTo: string; keeper: string; closes: number } {
  const parsed = parseElection(request)
  if (!parsed) throw new Error('not a recovery request')
  const m = /^unseal:(.+):\d+$/.exec(parsed.electionId)
  const to = /Shares to ([0-9a-f]{64})\./.exec(parsed.description ?? '')
  if (!m || !to) throw new Error('not a recovery request')
  return { epochId: m[1]!, recoverTo: to[1]!, keeper: request.pubkey, closes: parsed.closes }
}

export interface ReleaseOptions {
  memberPrivateKey: Uint8Array
  share: OpenedShare
  request: NostrEvent
  ballots: NostrEvent[]
  members: string[]
  now?: number
}

/**
 * A member hands their share back, wrapped to the key the request named,
 * and only when the time lock has passed with no refusal. Throws otherwise,
 * because a client must never be able to release early by mistake.
 */
export function releaseShare(opts: ReleaseOptions): NostrEvent {
  const details = requestDetails(opts.request)
  if (details.keeper !== opts.share.keeper) throw new Error('request is not from the keeper who sealed this share')
  if (details.epochId !== opts.share.epochId) throw new Error('request is for a different epoch')
  const outcome = recoveryOutcome(opts.request, opts.ballots, opts.members, opts.now)
  if (outcome !== 'allowed') throw new Error(`recovery is ${outcome}`)
  const memberPub = getPublicKey(opts.memberPrivateKey)
  const rumor = buildVaultShareEvent(memberPub, details.recoverTo, bytesToHex(opts.share.data), opts.share.epochId, SEALED_TIER)
  rumor.tags.push(['share', String(opts.share.index)], ['threshold', String(opts.share.threshold)], ['e', opts.request.id])
  return wrapEvent(rumor, opts.memberPrivateKey, details.recoverTo)
}
