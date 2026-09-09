import { bytesToHex, hexToBytes, randomBytes, utf8ToBytes } from '@noble/hashes/utils.js'
import { sha256 } from '@noble/hashes/sha2.js'
import { getPublicKey, verifyEvent } from 'nostr-tools/pure'
import { wrapEvent } from 'nostr-tools/nip59'
import { decrypt as nip44Decrypt, getConversationKey } from 'nostr-tools/nip44'
import type { NostrEvent } from 'nostr-tools/pure'
import { splitCK, reconstructCK } from 'dominion-protocol'
import { buildVaultShareEvent, parseVaultShare } from 'dominion-protocol/nostr'

/** The tier name a sealed epoch's shares carry in their dominion vault-share event. */
export const SEALED_TIER = 'sealed'
/** Shortest time lock a seal may commit to. */
export const MIN_DELAY_SECONDS = 3600

const HEX64 = /^[0-9a-f]{64}$/
const KIND_SEAL = 13

/**
 * The circle in one canonical order: deduplicated, sorted, lower-case hex.
 * Every hash over the circle, and every ring an election commits to, uses
 * this order, so two members never disagree about who the circle is.
 */
export function canonicalCircle(members: readonly string[]): string[] {
  const set = [...new Set(members)]
  if (set.some((m) => typeof m !== 'string' || !HEX64.test(m))) throw new Error('members must be lower-case 64-hex pubkeys')
  return set.sort()
}

/** sha256 of the canonical circle joined by commas: the same bytes nostr-anon-vote commits to as its ring hash. */
export function circleHash(members: readonly string[]): string {
  return bytesToHex(sha256(utf8ToBytes(canonicalCircle(members).join(','))))
}

/** Commitment to one share: sha256(index || data). Reveals nothing, since a share is 32 uniformly random bytes. */
export function shareCommitment(index: number, data: Uint8Array): string {
  return bytesToHex(sha256(new Uint8Array([index & 0xff, ...data])))
}

/** Commitment to the epoch key itself, so a reconstruction from mislabelled shares is caught rather than trusted. */
export function keyCommitment(key: Uint8Array): string {
  return bytesToHex(sha256(new Uint8Array([...utf8ToBytes('epoch-seal/key/v1'), ...key])))
}

export interface SealOptions {
  /** The 32-byte key the closed epoch's store is encrypted under. */
  epochKey: Uint8Array
  /** The epoch's id, as the store names it. No colon: the vault-share d tag is `epoch:tier`. */
  epochId: string
  /** The keeper's private key: the author of the shares and the only key that can ask for them back. */
  keeperPrivateKey: Uint8Array
  /** The circle: each member's x-only pubkey the share is wrapped to (their rendezvous key). */
  members: string[]
  /** How many members must hand back a share. */
  threshold: number
  /** The shortest time lock a recovery of this epoch may carry, in seconds. Members measure it from their own first sight of the request. */
  delaySeconds: number
  now?: () => number
}

export interface SealedShare {
  /** Which member this share went to. */
  member: string
  index: number
  /** The gift wrap to publish or hand to the member. Nothing of the share is visible on it. */
  wrap: NostrEvent
}

export interface Sealing {
  /** Random id of this sealing; every share carries it and shares from different sealings never mix. */
  sealId: string
  /** Hash of the canonical circle the epoch was sealed to. */
  circle: string
  /** The committed delay. */
  delaySeconds: number
  /** Commitment per share index, in index order. The keeper may keep these; they reveal nothing. */
  commitments: string[]
  shares: SealedShare[]
}

/**
 * Split an epoch key across the circle and wrap one share to each member.
 *
 * Each share is a dominion kind 30480 vault-share rumor (tier `sealed`,
 * content the 32-byte share) carrying the share index, the threshold, the
 * sealing id, the circle hash and the circle itself, the committed delay,
 * a commitment to the epoch key and a commitment to every share of the
 * sealing. It is sealed by the keeper and gift-wrapped to the
 * member, so a relay sees only a wrap to a key. The keeper then destroys the
 * epoch key locally; that destruction is what makes compulsion yield the
 * current epoch and nothing older.
 */
export function sealEpoch(opts: SealOptions): Sealing {
  const members = canonicalCircle(opts.members)
  if (members.length < 2) throw new Error('a circle needs at least two members')
  if (!Number.isInteger(opts.threshold) || opts.threshold < 2 || opts.threshold > members.length) throw new Error('threshold must be between 2 and the number of members')
  if (!(opts.epochKey instanceof Uint8Array) || opts.epochKey.length !== 32) throw new Error('epoch key must be 32 bytes')
  if (typeof opts.epochId !== 'string' || !opts.epochId || opts.epochId.includes(':')) throw new Error('epoch id must be a non-empty string without a colon')
  if (!Number.isInteger(opts.delaySeconds) || opts.delaySeconds < MIN_DELAY_SECONDS) throw new Error(`delay must be at least ${MIN_DELAY_SECONDS} seconds`)
  const keeperPub = getPublicKey(opts.keeperPrivateKey)
  if (members.includes(keeperPub)) throw new Error('the keeper is not a member of its own circle')
  const sealId = bytesToHex(randomBytes(16))
  const circle = circleHash(members)
  const keyCommit = keyCommitment(opts.epochKey)
  const raw = splitCK(opts.epochKey, opts.threshold, members.length)
  const byIndex = [...raw].sort((a, b) => a.index - b.index)
  const commitments = byIndex.map((s) => shareCommitment(s.index, s.data))
  const shares = byIndex.map((share, i) => {
    const member = members[i]!
    const rumor = buildVaultShareEvent(keeperPub, member, bytesToHex(share.data), opts.epochId, SEALED_TIER)
    rumor.tags.push(
      ['share', String(share.index)],
      ['threshold', String(opts.threshold)],
      ['seal', sealId],
      ['circle', circle],
      ['members', ...members],
      ['delay', String(opts.delaySeconds)],
      ['keycommit', keyCommit],
      ...commitments.map((c, j) => ['commit', String(byIndex[j]!.index), c]),
    )
    if (opts.now) rumor.created_at = opts.now()
    return { member, index: share.index, wrap: wrapEvent(rumor, opts.keeperPrivateKey, member) }
  })
  return { sealId, circle, delaySeconds: opts.delaySeconds, commitments, shares }
}

export interface OpenedShare {
  /** Who authored the rumor: the keeper on a fresh share, the member on a returned one. */
  keeper: string
  epochId: string
  index: number
  threshold: number
  sealId: string
  circle: string
  /** The canonical circle itself, so every member can refuse and release without being told the list by the keeper. */
  members: string[]
  delaySeconds: number
  /** Commitment to the epoch key, checked after reconstruction. */
  keyCommitment: string
  /** Commitment per index for the whole sealing, keyed by index. */
  commitments: Map<number, string>
  data: Uint8Array
}

function tagValue(tags: string[][], name: string): string | undefined {
  const ts = tags.filter((t) => t[0] === name)
  return ts.length === 1 ? ts[0]![1] : undefined
}

/**
 * Open a gift wrap by hand. nostr-tools' unwrapEvent verifies nothing: it
 * decrypts twice and hands back whatever is inside. Here the seal must be a
 * validly signed kind 13 and the rumor's author must be the seal's signer,
 * otherwise anyone who can encrypt to the member could hand them a "share"
 * in the keeper's name.
 */
function unwrapVerified(wrap: NostrEvent, memberPrivateKey: Uint8Array): { rumor: Record<string, unknown>; sealer: string } {
  if (!wrap || typeof wrap !== 'object' || typeof wrap.content !== 'string' || !HEX64.test(wrap.pubkey ?? '')) throw new Error('not a gift wrap')
  const seal = JSON.parse(nip44Decrypt(wrap.content, getConversationKey(memberPrivateKey, wrap.pubkey))) as NostrEvent
  if (!seal || typeof seal !== 'object' || seal.kind !== KIND_SEAL || typeof seal.content !== 'string') throw new Error('not a seal')
  if (!Array.isArray(seal.tags) || seal.tags.length !== 0) throw new Error('a seal carries no tags')
  const bare = { kind: seal.kind, pubkey: seal.pubkey, created_at: seal.created_at, tags: seal.tags, content: seal.content, id: seal.id, sig: seal.sig }
  if (!verifyEvent(bare)) throw new Error('seal signature does not verify')
  const rumor = JSON.parse(nip44Decrypt(seal.content, getConversationKey(memberPrivateKey, seal.pubkey))) as Record<string, unknown>
  if (!rumor || typeof rumor !== 'object' || rumor.pubkey !== seal.pubkey) throw new Error('rumor author is not the sealer')
  return { rumor, sealer: seal.pubkey }
}

/** A member opens the wrap addressed to them and gets their share, verified as the sealer's. */
export function openShare(wrap: NostrEvent, memberPrivateKey: Uint8Array): OpenedShare {
  const { rumor, sealer } = unwrapVerified(wrap, memberPrivateKey)
  const parsed = parseVaultShare(rumor)
  if (!parsed || parsed.tier !== SEALED_TIER || parsed.fromPubkey !== sealer) throw new Error('not a sealed share')
  const tags = rumor.tags as string[][]
  const index = Number(tagValue(tags, 'share'))
  const threshold = Number(tagValue(tags, 'threshold'))
  const sealId = tagValue(tags, 'seal')
  const circle = tagValue(tags, 'circle')
  const delaySeconds = Number(tagValue(tags, 'delay'))
  if (!Number.isInteger(index) || index < 1 || index > 255) throw new Error('malformed sealed share')
  if (!Number.isInteger(threshold) || threshold < 2) throw new Error('malformed sealed share')
  if (!sealId || !/^[0-9a-f]{32}$/.test(sealId) || !circle || !HEX64.test(circle)) throw new Error('malformed sealed share')
  if (!Number.isInteger(delaySeconds) || delaySeconds < MIN_DELAY_SECONDS) throw new Error('malformed sealed share')
  if (parsed.epochId.includes(':') || tagValue(tags, 'd') !== `${parsed.epochId}:${SEALED_TIER}`) throw new Error('malformed sealed share')
  const membersTag = tags.filter((t) => t[0] === 'members')
  if (membersTag.length !== 1) throw new Error('malformed sealed share')
  const members = membersTag[0]!.slice(1)
  let canonical: string[]
  try { canonical = canonicalCircle(members) } catch { throw new Error('malformed sealed share') }
  if (canonical.length !== members.length || canonical.some((m, i) => m !== members[i]) || circleHash(canonical) !== circle) throw new Error('share names a circle that does not match its hash')
  const keyCommit = tagValue(tags, 'keycommit')
  if (!keyCommit || !HEX64.test(keyCommit)) throw new Error('malformed sealed share')
  const commitments = new Map<number, string>()
  for (const t of tags) {
    if (t[0] !== 'commit') continue
    const i = Number(t[1])
    if (!Number.isInteger(i) || i < 1 || i > 255 || !HEX64.test(t[2] ?? '') || commitments.has(i)) throw new Error('malformed sealed share')
    commitments.set(i, t[2]!)
  }
  if (commitments.size < threshold || !commitments.has(index)) throw new Error('malformed sealed share')
  const to = tagValue(tags, 'p')
  if (to !== getPublicKey(memberPrivateKey)) throw new Error('this share was not sealed to this member')
  const data = hexToBytes(parsed.ckHex)
  if (shareCommitment(index, data) !== commitments.get(index)) throw new Error('share does not match its commitment')
  return { keeper: sealer, epochId: parsed.epochId, index, threshold, sealId, circle, members: canonical, delaySeconds, keyCommitment: keyCommit, commitments, data }
}

export interface RecoverOptions {
  /** What the keeper recorded at sealing time, if kept. Returned shares are then checked against it, not only against each other. */
  expected?: { sealId: string; commitments: string[] }
}

/** Thrown by recoverEpoch when a share fails its commitment. `index` names the share, and so the member. */
export class PoisonedShareError extends Error {
  constructor(public readonly index: number, message: string) {
    super(message)
    this.name = 'PoisonedShareError'
  }
}

/** Thrown when the shares do not agree on what the sealing was and no set has a threshold behind it, so nobody can be blamed. */
export class ShareSetError extends Error {
  constructor(public readonly indices: number[], message: string) {
    super(message)
    this.name = 'ShareSetError'
  }
}

function setKey(m: Map<number, string>): string {
  return [...m].sort((a, b) => a[0] - b[0]).map(([i, c]) => `${i}:${c}`).join(',')
}

/**
 * Reconstruct the epoch key from `threshold` distinct shares of one sealing.
 * The commitment set every share is checked against is the one the keeper
 * kept (`expected`), or else the set a strict majority of the returned
 * shares agree on; a share that does not match it is refused by index,
 * which the recovering keeper can map to the member who returned it. When
 * no set has a majority nobody is blamed: `ShareSetError` names every
 * index that disagrees with the first. The reconstruction is then
 * checked against the key commitment, so mislabelled shares yield an error
 * rather than a wrong key.
 */
export function recoverEpoch(shares: OpenedShare[], opts: RecoverOptions = {}): Uint8Array {
  if (!Array.isArray(shares) || shares.length === 0) throw new Error('no shares')
  const first = shares[0]!
  const { epochId, threshold, sealId, keyCommitment: kc } = first
  if (opts.expected && opts.expected.sealId !== sealId) throw new Error('shares are not from the expected sealing')
  for (const s of shares) {
    if (s.epochId !== epochId || s.threshold !== threshold || s.sealId !== sealId || s.keyCommitment !== kc || s.circle !== first.circle) throw new Error('shares are not from one sealing')
  }
  let reference: Map<number, string>
  if (opts.expected) {
    reference = new Map(opts.expected.commitments.map((c, i) => [i + 1, c]))
  } else {
    const groups = new Map<string, { set: Map<number, string>; indices: number[] }>()
    for (const s of shares) {
      const k = setKey(s.commitments)
      const g = groups.get(k) ?? { set: s.commitments, indices: [] }
      g.indices.push(s.index)
      groups.set(k, g)
    }
    // The reference is the set a strict majority of the returned shares carry.
    // One attacker among three is named; one against one is a tie, and a tie
    // blames nobody.
    const total = new Set(shares.map((s) => s.index)).size
    const majority = [...groups.values()].filter((g) => new Set(g.indices).size * 2 > total)
    if (majority.length !== 1) {
      const firstKey = setKey(first.commitments)
      throw new ShareSetError(shares.filter((s) => setKey(s.commitments) !== firstKey).map((s) => s.index), 'shares disagree about the sealing and no set has a majority behind it')
    }
    reference = majority[0]!.set
  }
  for (const s of shares) {
    if (s.commitments.size !== reference.size || [...reference].some(([i, c]) => s.commitments.get(i) !== c)) {
      throw new PoisonedShareError(s.index, `share ${s.index} carries a different commitment set`)
    }
    if (shareCommitment(s.index, s.data) !== reference.get(s.index)) throw new PoisonedShareError(s.index, `share ${s.index} does not match its commitment`)
  }
  const distinct = new Map(shares.map((s) => [s.index, s]))
  if (distinct.size < threshold) throw new Error(`need ${threshold} distinct shares, have ${distinct.size}`)
  const chosen = [...distinct.values()].slice(0, threshold)
  const key = reconstructCK(chosen.map((s) => ({ index: s.index, data: s.data })))
  if (keyCommitment(key) !== kc) throw new Error('reconstructed key does not match its commitment: the threshold or the shares were mislabelled')
  return key
}
