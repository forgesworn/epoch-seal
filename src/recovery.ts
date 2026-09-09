import { bytesToHex, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { finalizeEvent, generateSecretKey, getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { wrapEvent } from 'nostr-tools/nip59'
import type { NostrEvent } from 'nostr-tools/pure'
import { createElection, encryptBallotContent, parseElection, verifyBallot } from 'nostr-anon-vote'
import { computeKeyImage, lsagSign } from '@forgesworn/ring-sig'
import { buildVaultShareEvent } from 'dominion-protocol/nostr'
import { SEALED_TIER, MIN_DELAY_SECONDS, canonicalCircle, circleHash, type OpenedShare } from './seal.js'

export const REFUSE = 'refuse'
export const ALLOW = 'allow'
/** How long after the lock passes a member will still release. A stale "allowed" request is not a standing licence. */
export const RELEASE_WINDOW_SECONDS = 7 * 24 * 3600

const HEX64 = /^[0-9a-f]{64}$/
const ID_RE = /^unseal:([^:]+):(\d+):([0-9a-f]{16})$/
const DESC_RE = /^Shares to ([0-9a-f]{64})\. A ballot is a refusal\. Silence until close is consent\.$/

export interface RecoveryRequestOptions {
  keeperPrivateKey: Uint8Array
  epochId: string
  /** The circle's rendezvous pubkeys, exactly the set the epoch was sealed to. */
  members: string[]
  /** The time lock: seconds from now before shares may be released. Members refuse anything shorter than the delay the seal committed to. */
  delaySeconds: number
  /** Where the shares should come back to. Usually the keeper's current rendezvous key. */
  recoverTo: string
  now?: () => number
}

/**
 * Ask the circle for an old epoch back. The request is an anonymous-vote
 * election over the canonical circle whose only meaningful ballot is a
 * refusal: a member who is uneasy casts one, ring-signed over the circle,
 * and nobody, the keeper included, learns which member it was. Consent is
 * silence until the time lock passes.
 */
export async function requestRecovery(opts: RecoveryRequestOptions): Promise<NostrEvent> {
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000)
  if (!Number.isInteger(opts.delaySeconds) || opts.delaySeconds < MIN_DELAY_SECONDS) throw new Error(`a recovery needs a time lock of at least ${MIN_DELAY_SECONDS} seconds`)
  if (typeof opts.epochId !== 'string' || !opts.epochId || opts.epochId.includes(':')) throw new Error('epoch id must be a non-empty string without a colon')
  if (!HEX64.test(opts.recoverTo)) throw new Error('recoverTo must be a lower-case 64-hex pubkey')
  const keeperPub = getPublicKey(opts.keeperPrivateKey)
  const ring = canonicalCircle(opts.members)
  if (ring.length < 2) throw new Error('a circle needs at least two members')
  return createElection(bytesToHex(opts.keeperPrivateKey), {
    electionId: `unseal:${opts.epochId}:${now}:${bytesToHex(randomBytes(8))}`,
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

export interface RefuseOptions {
  now?: () => number
}

/**
 * A member refuses. The ballot names no one: it is a ring signature over
 * the circle the share carries, bound to this request. It is built here
 * rather than by nostr-anon-vote's `castBallot`, which refuses to cast once
 * the wall clock is past the request's close; a request dated into the past
 * would then have no refusers while every release gate still passed. A
 * refusal can be cast at any time, and the reading side counts it whenever
 * it was cast. The circle comes from the member's own share, so the keeper
 * cannot choose who is able to refuse by choosing who is told the list.
 */
export async function refuse(memberPrivateKey: Uint8Array, request: NostrEvent, share: OpenedShare, opts: RefuseOptions = {}): Promise<NostrEvent> {
  const details = requestDetails(request)
  if (details.keeper !== share.keeper || details.epochId !== share.epochId) throw new Error('request is not for the epoch this share seals')
  const ring = share.members
  if (circleHash(ring) !== details.circle) throw new Error('request names a different circle from the one this share was sealed to')
  const me = getPublicKey(memberPrivateKey)
  const signerIndex = ring.indexOf(me)
  if (signerIndex === -1) throw new Error('this key is not in the circle')
  const priv = bytesToHex(memberPrivateKey)
  const keyImage = computeKeyImage(priv, me, details.electionId)
  const encryptedVote = await encryptBallotContent(JSON.stringify({ option: REFUSE }), details.keeper)
  const message = `${details.electionId}:${bytesToHex(sha256(utf8ToBytes(encryptedVote)))}`
  const sig = lsagSign(message, ring, signerIndex, priv, details.electionId)
  const content: Record<string, unknown> = { c0: sig.c0, electionId: sig.electionId, message: sig.message, responses: sig.responses }
  if (sig.domain !== undefined) content.domain = sig.domain
  const now = opts.now ? opts.now() : Math.floor(Date.now() / 1000)
  return finalizeEvent({
    kind: 30483,
    created_at: now,
    tags: [
      ['d', `${details.electionId}:${bytesToHex(randomBytes(16))}`],
      ['election', request.id],
      ['key-image', keyImage],
      ['encrypted-vote', encryptedVote],
      ['algo', 'secp256k1'],
      ['L', 'anon-vote'],
      ['l', 'anon-vote'],
    ],
    content: JSON.stringify(content),
  }, generateSecretKey())
}

export interface RequestDetails {
  epochId: string
  recoverTo: string
  keeper: string
  /** The election's `d` tag: `unseal:<epoch>:<time>:<random>`. */
  electionId: string
  opens: number
  closes: number
  /** The circle hash the request committed to as its ring. */
  circle: string
}

/**
 * The epoch a request is for, where the shares should go, and what it
 * committed to. Throws unless the request is a validly signed election of
 * exactly the shape requestRecovery makes: any other event is not a request,
 * however much it resembles one.
 */
export function requestDetails(request: NostrEvent): RequestDetails {
  if (!request || typeof request !== 'object' || !Array.isArray(request.tags) || !request.tags.every((t) => Array.isArray(t) && t.every((x) => typeof x === 'string'))) {
    throw new Error('not a recovery request')
  }
  const bare = { kind: request.kind, pubkey: request.pubkey, created_at: request.created_at, tags: request.tags, content: request.content, id: request.id, sig: request.sig }
  if (!verifyEvent(bare)) throw new Error('not a recovery request')
  const parsed = parseElection(request)
  if (!parsed) throw new Error('not a recovery request')
  const m = ID_RE.exec(parsed.electionId)
  const to = DESC_RE.exec(parsed.description ?? '')
  if (!m || !to) throw new Error('not a recovery request')
  if (parsed.options.length !== 2 || parsed.options[0] !== REFUSE || parsed.options[1] !== ALLOW) throw new Error('not a recovery request')
  if (parsed.tallyPubkeys.length !== 1 || parsed.tallyPubkeys[0] !== request.pubkey) throw new Error('not a recovery request')
  if (parsed.reVote !== 'denied') throw new Error('not a recovery request')
  if (!parsed.ringHash || !HEX64.test(parsed.ringHash)) throw new Error('request commits to no circle')
  if (!Number.isSafeInteger(parsed.opens) || !Number.isSafeInteger(parsed.closes) || parsed.closes <= parsed.opens) throw new Error('not a recovery request')
  return { epochId: m[1]!, recoverTo: to[1]!, keeper: request.pubkey, electionId: parsed.electionId, opens: parsed.opens, closes: parsed.closes, circle: parsed.ringHash }
}

export type Outcome = 'pending' | 'refused' | 'allowed' | 'expired'

/**
 * verifyBallot failures that do not make a ballot any less a refusal of this
 * request: when it was cast, and which signed copy of the request it names.
 * The ring signature is bound to the election id (the `d` tag, which carries
 * the epoch, the time and a random suffix), to the ring and to the vote
 * ciphertext, so a ballot that passes everything but these was cast by a
 * member of this circle against this keeper's request for this epoch.
 */
const TOLERATED = /^(Ballot was created before election opened|Ballot was created after election closed|Ballot timestamp is in the future|Ballot election reference does not match election event ID)$/

/**
 * Is this ballot a refusal? A refusal is any validly signed ballot whose
 * ring signature verifies over this request's circle and is bound to this
 * request's election id. When it was cast does not matter: a member who
 * says no after the clock ran out has still said no, and a client that
 * discarded it for its timestamp would release over an objection. Nor does
 * it matter which signed copy of the request it names: a keeper who
 * re-issues the same election id with a new destination does not shake off
 * a refusal of the first copy.
 */
export function isRefusal(ballot: NostrEvent, request: NostrEvent, ring: string[]): boolean {
  if (!ballot || typeof ballot !== 'object' || !Array.isArray(ballot.tags) || !ballot.tags.every((t) => Array.isArray(t) && t.every((x) => typeof x === 'string'))) return false
  const bare = { kind: ballot.kind, pubkey: ballot.pubkey, created_at: ballot.created_at, tags: ballot.tags, content: ballot.content, id: ballot.id, sig: ballot.sig }
  if (!verifyEvent(bare)) return false
  let result: { valid: boolean; errors: string[] }
  try { result = verifyBallot(ballot, request, ring) } catch { return false }
  return result.valid || result.errors.every((e) => TOLERATED.test(e))
}

/**
 * What the circle has decided. Any refusal, whenever cast, is a refusal, so
 * members can judge the outcome without the tally key. The members given
 * must be the circle the request committed to; anything else is not a
 * verdict, it is an error.
 */
export function recoveryOutcome(request: NostrEvent, ballots: NostrEvent[], members: string[], now = Math.floor(Date.now() / 1000)): Outcome {
  const details = requestDetails(request)
  const ring = canonicalCircle(members)
  if (circleHash(ring) !== details.circle) throw new Error('these members are not the circle the request names')
  if (!Array.isArray(ballots)) throw new Error('ballots must be an array')
  if (ballots.some((b) => isRefusal(b, request, ring))) return 'refused'
  if (now < details.closes) return 'pending'
  return now <= details.closes + RELEASE_WINDOW_SECONDS ? 'allowed' : 'expired'
}

export interface ReleaseOptions {
  memberPrivateKey: Uint8Array
  share: OpenedShare
  request: NostrEvent
  ballots: NostrEvent[]
  /** When this member first saw the request, by their own clock. The seal's delay is measured from here, never from the request's own dates. */
  firstSeen: number
  now?: number
}

/**
 * A member hands their share back, wrapped to the key the request named,
 * and only when: the request is the sealing keeper's, for this epoch, over
 * the circle the share was sealed to; its lock is no shorter than the delay
 * the seal committed to; the lock had not already closed when this member
 * first saw it; that delay has passed since this member first saw it; the
 * lock has passed with no refusal; and the release window is still open.
 * Throws otherwise, because a client must never be able to release early
 * by mistake. A client SHOULD wait a grace period after the delay before
 * calling this, so a refusal cast at the last moment has time to arrive.
 */
export function releaseShare(opts: ReleaseOptions): NostrEvent {
  const now = opts.now ?? Math.floor(Date.now() / 1000)
  const details = requestDetails(opts.request)
  const share = opts.share
  if (details.keeper !== share.keeper) throw new Error('request is not from the keeper who sealed this share')
  if (details.epochId !== share.epochId) throw new Error('request is for a different epoch')
  if (details.circle !== share.circle) throw new Error('request names a different circle from the one this share was sealed to')
  if (details.closes - details.opens < share.delaySeconds) throw new Error(`request lock is shorter than the sealed delay of ${share.delaySeconds} seconds`)
  if (!Number.isSafeInteger(opts.firstSeen) || opts.firstSeen <= 0 || opts.firstSeen > now) throw new Error('firstSeen is required: when this member first saw the request, no later than now')
  // A request whose lock had already closed when this member first saw it was dated into the
  // past: the window in which the circle could refuse is gone, so nothing is released.
  if (opts.firstSeen >= details.closes) throw new Error('request had already closed when this member first saw it')
  if (now < opts.firstSeen + share.delaySeconds) throw new Error('recovery is pending: the sealed delay has not passed since this member first saw the request')
  const outcome = recoveryOutcome(opts.request, opts.ballots, share.members, now)
  if (outcome !== 'allowed') throw new Error(`recovery is ${outcome}`)
  const memberPub = getPublicKey(opts.memberPrivateKey)
  const rumor = buildVaultShareEvent(memberPub, details.recoverTo, bytesToHex(share.data), share.epochId, SEALED_TIER)
  rumor.tags.push(
    ['share', String(share.index)],
    ['threshold', String(share.threshold)],
    ['seal', share.sealId],
    ['circle', share.circle],
    ['members', ...share.members],
    ['delay', String(share.delaySeconds)],
    ['keycommit', share.keyCommitment],
    ...[...share.commitments].sort((a, b) => a[0] - b[0]).map(([i, c]) => ['commit', String(i), c]),
    ['e', opts.request.id],
  )
  return wrapEvent(rumor, opts.memberPrivateKey, details.recoverTo)
}
