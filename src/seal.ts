import { bytesToHex, hexToBytes } from '@noble/hashes/utils.js'
import { getPublicKey } from 'nostr-tools/pure'
import { unwrapEvent, wrapEvent } from 'nostr-tools/nip59'
import type { NostrEvent } from 'nostr-tools/pure'
import { splitCK, reconstructCK } from 'dominion-protocol'
import { buildVaultShareEvent, parseVaultShare } from 'dominion-protocol/nostr'

/** The tier name a sealed epoch's shares carry in their dominion vault-share event. */
export const SEALED_TIER = 'sealed'

export interface SealOptions {
  /** The 32-byte key the closed epoch's store is encrypted under. */
  epochKey: Uint8Array
  /** The epoch's id, as the store names it. */
  epochId: string
  /** The keeper's private key: the author of the shares and the only key that can ask for them back. */
  keeperPrivateKey: Uint8Array
  /** The circle: each member's x-only pubkey the share is wrapped to (their rendezvous key). */
  members: string[]
  /** How many members must hand back a share. */
  threshold: number
  now?: () => number
}

export interface SealedShare {
  /** Which member this share went to. */
  member: string
  index: number
  /** The gift wrap to publish or hand to the member. Nothing of the share is visible on it. */
  wrap: NostrEvent
}

/**
 * Split an epoch key across the circle and wrap one share to each member.
 *
 * Each share is a dominion kind 30480 vault-share rumor (tier `sealed`,
 * content the 32-byte share, index in a `share` tag), sealed by the keeper
 * and gift-wrapped to the member, so a relay sees only a wrap to a key.
 * The keeper then destroys the epoch key locally; that destruction is what
 * makes compulsion yield the current epoch and nothing older.
 */
export function sealEpoch(opts: SealOptions): SealedShare[] {
  const members = [...new Set(opts.members)]
  if (members.length < 2) throw new Error('a circle needs at least two members')
  if (opts.threshold < 2 || opts.threshold > members.length) throw new Error('threshold must be between 2 and the number of members')
  if (opts.epochKey.length !== 32) throw new Error('epoch key must be 32 bytes')
  const keeperPub = getPublicKey(opts.keeperPrivateKey)
  const shares = splitCK(opts.epochKey, opts.threshold, members.length)
  return shares.map((share, i) => {
    const member = members[i]!
    const rumor = buildVaultShareEvent(keeperPub, member, bytesToHex(share.data), opts.epochId, SEALED_TIER)
    rumor.tags.push(['share', String(share.index)], ['threshold', String(opts.threshold)])
    if (opts.now) rumor.created_at = opts.now()
    return { member, index: share.index, wrap: wrapEvent(rumor, opts.keeperPrivateKey, member) }
  })
}

export interface OpenedShare {
  /** The keeper who sealed it. */
  keeper: string
  epochId: string
  index: number
  threshold: number
  data: Uint8Array
}

/** A member opens the wrap addressed to them and gets their share, verified as the keeper's. */
export function openShare(wrap: NostrEvent, memberPrivateKey: Uint8Array): OpenedShare {
  const rumor = unwrapEvent(wrap, memberPrivateKey)
  const parsed = parseVaultShare(rumor as unknown as Record<string, unknown>)
  if (!parsed || parsed.tier !== SEALED_TIER) throw new Error('not a sealed share')
  const index = Number(rumor.tags.find((t) => t[0] === 'share')?.[1])
  const threshold = Number(rumor.tags.find((t) => t[0] === 'threshold')?.[1])
  if (!Number.isInteger(index) || index < 1 || !Number.isInteger(threshold) || threshold < 2) throw new Error('malformed sealed share')
  const to = rumor.tags.find((t) => t[0] === 'p')?.[1]
  if (to !== getPublicKey(memberPrivateKey)) throw new Error('this share was not sealed to this member')
  return { keeper: parsed.fromPubkey, epochId: parsed.epochId, index, threshold, data: hexToBytes(parsed.ckHex) }
}

/**
 * Reconstruct the epoch key from exactly `threshold` distinct shares for one
 * epoch. Shares that come back through `releaseShare` are authored by the
 * member who held them, so authorship is not compared here; the keeper
 * recovering knows whose shares they asked for, and a wrong share simply
 * yields the wrong key, which the store's own authentication rejects.
 */
export function recoverEpoch(shares: OpenedShare[]): Uint8Array {
  if (shares.length === 0) throw new Error('no shares')
  const { epochId, threshold } = shares[0]!
  if (shares.some((s) => s.epochId !== epochId || s.threshold !== threshold)) throw new Error('shares are not from one sealing')
  const distinct = new Map(shares.map((s) => [s.index, s]))
  if (distinct.size < threshold) throw new Error(`need ${threshold} distinct shares, have ${distinct.size}`)
  const chosen = [...distinct.values()].slice(0, threshold)
  return reconstructCK(chosen.map((s) => ({ index: s.index, data: s.data })))
}
