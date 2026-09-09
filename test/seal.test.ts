import { describe, it, expect } from 'vitest'
import { generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { unwrapEvent } from 'nostr-tools/nip59'
import { bytesToHex } from '@noble/hashes/utils.js'
import { sealEpoch, openShare, recoverEpoch, requestRecovery, refuse, recoveryOutcome, releaseShare, requestDetails } from '../src/index.js'

const keeper = generateSecretKey()
const keeperPub = getPublicKey(keeper)
const circle = Array.from({ length: 5 }, () => generateSecretKey())
const members = circle.map(getPublicKey)
const epochKey = new Uint8Array(32).map((_, i) => (i * 37 + 11) & 0xff)
const EPOCH = '2026-W37'
const recoveryKey = generateSecretKey()
const recoverTo = getPublicKey(recoveryKey)

describe('sealing', () => {
  it('splits 3-of-5, each share opens only for its member, and any three rebuild the key', () => {
    const sealed = sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 3 })
    expect(sealed.length).toBe(5)
    for (const s of sealed) {
      const wire = JSON.stringify(s.wrap)
      expect(wire.includes(keeperPub)).toBe(false)
      expect(wire.includes(bytesToHex(epochKey))).toBe(false)
      expect(s.wrap.tags.find((t) => t[0] === 'p')![1]).toBe(s.member)
    }
    const opened = sealed.map((s, i) => openShare(s.wrap, circle[i]!))
    expect(opened.every((o) => o.keeper === keeperPub && o.epochId === EPOCH && o.threshold === 3)).toBe(true)
    expect(bytesToHex(recoverEpoch([opened[0]!, opened[2]!, opened[4]!]))).toBe(bytesToHex(epochKey))
    expect(bytesToHex(recoverEpoch([opened[1]!, opened[3]!, opened[4]!]))).toBe(bytesToHex(epochKey))
    expect(() => recoverEpoch([opened[0]!, opened[1]!])).toThrow(/need 3/)
    expect(() => openShare(sealed[0]!.wrap, circle[1]!)).toThrow()
  })
  it('refuses a bad threshold or a tiny circle', () => {
    expect(() => sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members: members.slice(0, 1), threshold: 1 })).toThrow()
    expect(() => sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 6 })).toThrow()
  })
})

describe('witnessed recovery', () => {
  it('a request is pending until the lock passes, then allowed, and shares come back to the named key', async () => {
    const sealed = sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 3 })
    const opened = sealed.map((s, i) => openShare(s.wrap, circle[i]!))
    const request = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: 3600, recoverTo })
    const d = requestDetails(request)
    expect(d.epochId).toBe(EPOCH)
    expect(d.recoverTo).toBe(recoverTo)
    expect(d.keeper).toBe(keeperPub)
    const now = Math.floor(Date.now() / 1000)
    expect(recoveryOutcome(request, [], members, now)).toBe('pending')
    expect(() => releaseShare({ memberPrivateKey: circle[0]!, share: opened[0]!, request, ballots: [], members, now })).toThrow(/pending/)
    const later = now + 3601
    expect(recoveryOutcome(request, [], members, later)).toBe('allowed')
    const returned = [0, 1, 2].map((i) => releaseShare({ memberPrivateKey: circle[i]!, share: opened[i]!, request, ballots: [], members, now: later }))
    const back = returned.map((w) => openShare(w, recoveryKey))
    expect(bytesToHex(recoverEpoch(back))).toBe(bytesToHex(epochKey))
    expect(back.every((b) => b.epochId === EPOCH)).toBe(true)
  })
  it('one anonymous refusal blocks it, and the refuser cannot be told from the ballot', async () => {
    const sealed = sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 3 })
    const opened = sealed.map((s, i) => openShare(s.wrap, circle[i]!))
    const request = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: 3600, recoverTo })
    const ballot = await refuse(circle[3]!, request, members)
    expect(members.includes(ballot.pubkey)).toBe(false)
    expect(JSON.stringify(ballot).includes(members[3]!)).toBe(false)
    const later = Math.floor(Date.now() / 1000) + 3601
    expect(recoveryOutcome(request, [ballot], members, later)).toBe('refused')
    expect(() => releaseShare({ memberPrivateKey: circle[0]!, share: opened[0]!, request, ballots: [ballot], members, now: later })).toThrow(/refused/)
    // A ballot from outside the circle is not a refusal.
    const stranger = generateSecretKey()
    await expect(refuse(stranger, request, members)).rejects.toThrow()
  })
  it('a request from the wrong keeper or for another epoch releases nothing', async () => {
    const sealed = sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 3 })
    const opened = sealed.map((s, i) => openShare(s.wrap, circle[i]!))
    const impostor = generateSecretKey()
    const later = Math.floor(Date.now() / 1000) + 3601
    const forged = await requestRecovery({ keeperPrivateKey: impostor, epochId: EPOCH, members, delaySeconds: 3600, recoverTo })
    expect(() => releaseShare({ memberPrivateKey: circle[0]!, share: opened[0]!, request: forged, ballots: [], members, now: later })).toThrow(/keeper/)
    const other = await requestRecovery({ keeperPrivateKey: keeper, epochId: '2026-W38', members, delaySeconds: 3600, recoverTo })
    expect(() => releaseShare({ memberPrivateKey: circle[0]!, share: opened[0]!, request: other, ballots: [], members, now: later })).toThrow(/epoch/)
    void unwrapEvent
  })
})
