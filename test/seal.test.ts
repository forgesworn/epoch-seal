import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import { createSeal, createWrap, createRumor } from 'nostr-tools/nip59'
import { bytesToHex } from '@noble/hashes/utils.js'
import {
  sealEpoch, openShare, recoverEpoch, requestRecovery, refuse, recoveryOutcome, releaseShare, requestDetails, isRefusal,
  circleHash, PoisonedShareError, RELEASE_WINDOW_SECONDS, MIN_DELAY_SECONDS,
} from '../src/index.js'

const keeper = generateSecretKey()
const keeperPub = getPublicKey(keeper)
const circle = Array.from({ length: 5 }, () => generateSecretKey())
const members = circle.map(getPublicKey)
const epochKey = new Uint8Array(32).map((_, i) => (i * 37 + 11) & 0xff)
const EPOCH = '2026-W37'
const DELAY = 48 * 3600
const recoveryKey = generateSecretKey()
const recoverTo = getPublicKey(recoveryKey)
const nowSec = () => Math.floor(Date.now() / 1000)

function seal(opts: Partial<Parameters<typeof sealEpoch>[0]> = {}) {
  return sealEpoch({ epochKey, epochId: EPOCH, keeperPrivateKey: keeper, members, threshold: 3, delaySeconds: DELAY, ...opts })
}
/** Shares opened by their members, in the canonical (sorted) order sealEpoch uses. */
function openAll(s = seal()) {
  return s.shares.map((sh) => openShare(sh.wrap, circle[members.indexOf(sh.member)]!))
}

describe('sealing', () => {
  it('splits 3-of-5, each share opens only for its member, and any three rebuild the key', () => {
    const s = seal()
    expect(s.shares.length).toBe(5)
    expect(s.circle).toBe(circleHash(members))
    expect(s.commitments.length).toBe(5)
    for (const sh of s.shares) {
      const wire = JSON.stringify(sh.wrap)
      expect(wire.includes(keeperPub)).toBe(false)
      expect(wire.includes(bytesToHex(epochKey))).toBe(false)
      expect(wire.includes(s.sealId)).toBe(false)
      expect(sh.wrap.tags.find((t) => t[0] === 'p')![1]).toBe(sh.member)
    }
    const opened = openAll(s)
    expect(opened.every((o) => o.keeper === keeperPub && o.epochId === EPOCH && o.threshold === 3 && o.sealId === s.sealId && o.circle === s.circle && o.delaySeconds === DELAY)).toBe(true)
    expect(bytesToHex(recoverEpoch([opened[0]!, opened[2]!, opened[4]!]))).toBe(bytesToHex(epochKey))
    expect(bytesToHex(recoverEpoch([opened[1]!, opened[3]!, opened[4]!], { expected: { sealId: s.sealId, commitments: s.commitments } }))).toBe(bytesToHex(epochKey))
    expect(() => recoverEpoch([opened[0]!, opened[1]!])).toThrow(/need 3/)
    expect(() => openShare(s.shares[0]!.wrap, circle[(members.indexOf(s.shares[0]!.member) + 1) % 5]!)).toThrow()
  })
  it('refuses a bad threshold, a tiny circle, a short delay, a colon in the epoch id, or the keeper in its own circle', () => {
    expect(() => seal({ members: members.slice(0, 1), threshold: 1 })).toThrow()
    expect(() => seal({ threshold: 6 })).toThrow()
    expect(() => seal({ delaySeconds: MIN_DELAY_SECONDS - 1 })).toThrow(/delay/)
    expect(() => seal({ epochId: 'a:b' })).toThrow(/colon/)
    expect(() => seal({ members: [...members, keeperPub] })).toThrow(/keeper/)
    expect(() => seal({ members: [...members, 'ABCDEF'] })).toThrow(/hex/)
  })
  it('a wrap whose seal was not signed by the rumor author does not open', () => {
    const s = seal()
    const target = s.shares[0]!
    const memberPriv = circle[members.indexOf(target.member)]!
    const attacker = generateSecretKey()
    // A rumor claiming to be the keeper's, sealed and signed by someone else.
    const rumor = createRumor({ kind: 30480, created_at: nowSec(), tags: [['d', `${EPOCH}:sealed`], ['p', target.member], ['tier', 'sealed'], ['share', '1'], ['threshold', '3']], content: '00'.repeat(32) }, attacker)
    ;(rumor as { pubkey: string }).pubkey = keeperPub
    const forged = createWrap(createSeal(rumor, attacker, target.member), target.member)
    expect(() => openShare(forged, memberPriv)).toThrow(/sealer/)
    // A seal signed by the keeper but whose signature was broken in transit.
    const wire = JSON.parse(JSON.stringify(target.wrap))
    wire.pubkey = getPublicKey(generateSecretKey())
    expect(() => openShare(wire, memberPriv)).toThrow()
  })
  it('a poisoned or mixed share is refused and named by index', () => {
    const s = seal()
    const opened = openAll(s)
    const bad = { ...opened[1]!, data: new Uint8Array(opened[1]!.data).map((b, i) => (i === 3 ? b ^ 1 : b)) }
    let err: unknown
    try { recoverEpoch([opened[0]!, bad, opened[2]!]) } catch (e) { err = e }
    expect(err).toBeInstanceOf(PoisonedShareError)
    expect((err as PoisonedShareError).index).toBe(opened[1]!.index)
    const other = openAll(seal())
    expect(() => recoverEpoch([opened[0]!, other[1]!, opened[2]!])).toThrow(/one sealing/)
    expect(() => recoverEpoch([opened[0]!, opened[1]!, opened[2]!], { expected: { sealId: other[0]!.sealId, commitments: s.commitments } })).toThrow(/expected sealing/)
    // A share whose commitment list was rewritten on the way back.
    const rewritten = { ...opened[2]!, commitments: new Map([...opened[2]!.commitments].map(([i, c]) => [i, i === 1 ? '00'.repeat(32) : c])) }
    expect(() => recoverEpoch([opened[0]!, opened[1]!, rewritten])).toThrow(PoisonedShareError)
  })
})

describe('witnessed recovery', () => {
  it('a request is pending until the lock and the sealed delay pass, then allowed, and shares come back to the named key', async () => {
    const s = seal()
    const opened = openAll(s)
    const now = nowSec()
    const request = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: DELAY, recoverTo, now: () => now })
    const d = requestDetails(request)
    expect(d.epochId).toBe(EPOCH)
    expect(d.recoverTo).toBe(recoverTo)
    expect(d.keeper).toBe(keeperPub)
    expect(d.circle).toBe(s.circle)
    expect(recoveryOutcome(request, [], members, now)).toBe('pending')
    const rel = (i: number, at: number, firstSeen = now) => releaseShare({ memberPrivateKey: circle[members.indexOf(s.shares[i]!.member)]!, share: opened[i]!, request, ballots: [], members, firstSeen, now: at })
    expect(() => rel(0, now)).toThrow(/pending/)
    const later = now + DELAY + 1
    expect(recoveryOutcome(request, [], members, later)).toBe('allowed')
    // The member who first saw the request an hour before the lock ends waits the full sealed delay from their own sight.
    expect(() => rel(0, later, later - 3600)).toThrow(/first saw/)
    const returned = [0, 1, 2].map((i) => rel(i, later))
    const back = returned.map((w) => openShare(w, recoveryKey))
    expect(back.every((b) => b.epochId === EPOCH && b.sealId === s.sealId && b.circle === s.circle)).toBe(true)
    expect(bytesToHex(recoverEpoch(back, { expected: { sealId: s.sealId, commitments: s.commitments } }))).toBe(bytesToHex(epochKey))
    // After the release window a stale request releases nothing.
    const stale = now + DELAY + RELEASE_WINDOW_SECONDS + 1
    expect(recoveryOutcome(request, [], members, stale)).toBe('expired')
    expect(() => rel(0, stale)).toThrow(/expired/)
  })
  it('a request with a lock shorter than the sealed delay releases nothing even after it closes', async () => {
    const s = seal()
    const opened = openAll(s)
    const now = nowSec()
    const short = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: MIN_DELAY_SECONDS, recoverTo, now: () => now })
    const far = now + MIN_DELAY_SECONDS + RELEASE_WINDOW_SECONDS + 1
    expect(recoveryOutcome(short, [], members, far)).toBe('expired')
    expect(() => releaseShare({ memberPrivateKey: circle[members.indexOf(s.shares[0]!.member)]!, share: opened[0]!, request: short, ballots: [], members, firstSeen: now, now: now + MIN_DELAY_SECONDS + 1 })).toThrow(/shorter than the sealed delay/)
  })
  it('one anonymous refusal blocks it, the refuser cannot be told from the ballot, and a late refusal still counts', async () => {
    const s = seal()
    const opened = openAll(s)
    const now = nowSec()
    const request = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: DELAY, recoverTo, now: () => now })
    const ballot = await refuse(circle[3]!, request, members)
    expect(members.includes(ballot.pubkey)).toBe(false)
    expect(JSON.stringify(ballot).includes(members[3]!)).toBe(false)
    const later = now + DELAY + 1
    expect(recoveryOutcome(request, [ballot], members, later)).toBe('refused')
    expect(() => releaseShare({ memberPrivateKey: circle[0]!, share: opened[0]!, request, ballots: [ballot], members, firstSeen: now, now: later })).toThrow(/refused/)
    // The same ring signature re-issued under a fresh ephemeral key, dated after close: still a refusal.
    const late = finalizeEvent({ kind: ballot.kind, created_at: requestDetails(request).closes + 10, tags: ballot.tags, content: ballot.content }, generateSecretKey())
    expect(isRefusal(late, request, [...members].sort())).toBe(true)
    expect(recoveryOutcome(request, [late], members, later)).toBe('refused')
    // A ballot whose event signature is broken is nothing.
    const broken = { ...ballot, content: ballot.content.replace(/"c0":"([0-9a-f])/, (_m, c) => `"c0":"${c === 'a' ? 'b' : 'a'}`) }
    expect(isRefusal(broken, request, [...members].sort())).toBe(false)
    const resigned = finalizeEvent({ kind: ballot.kind, created_at: ballot.created_at, tags: ballot.tags, content: broken.content }, generateSecretKey())
    expect(isRefusal(resigned, request, [...members].sort())).toBe(false)
    // A ballot from outside the circle is not a refusal.
    const stranger = generateSecretKey()
    await expect(refuse(stranger, request, members)).rejects.toThrow()
  })
  it('a request from the wrong keeper, for another epoch, over another circle, or with a broken signature releases nothing', async () => {
    const s = seal()
    const opened = openAll(s)
    const now = nowSec()
    const later = now + DELAY + 1
    const rel = (request: Parameters<typeof releaseShare>[0]['request'], mem = members) => releaseShare({ memberPrivateKey: circle[members.indexOf(s.shares[0]!.member)]!, share: opened[0]!, request, ballots: [], members: mem, firstSeen: now, now: later })
    const impostor = generateSecretKey()
    const forged = await requestRecovery({ keeperPrivateKey: impostor, epochId: EPOCH, members, delaySeconds: DELAY, recoverTo, now: () => now })
    expect(() => rel(forged)).toThrow(/keeper/)
    const other = await requestRecovery({ keeperPrivateKey: keeper, epochId: '2026-W38', members, delaySeconds: DELAY, recoverTo, now: () => now })
    expect(() => rel(other)).toThrow(/epoch/)
    // The keeper asks a circle of their own choosing: three of five swapped for keys they hold.
    const stooges = [members[0]!, members[1]!, ...Array.from({ length: 3 }, () => getPublicKey(generateSecretKey()))]
    const packed = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members: stooges, delaySeconds: DELAY, recoverTo, now: () => now })
    expect(() => rel(packed, stooges)).toThrow(/different circle/)
    expect(() => rel(packed)).toThrow(/different circle/)
    expect(() => recoveryOutcome(packed, [], members, later)).toThrow(/not the circle/)
    // A genuine request with one byte of the description changed.
    const genuine = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: DELAY, recoverTo, now: () => now })
    const tampered = { ...genuine, tags: genuine.tags.map((t) => (t[0] === 'description' ? ['description', t[1]!.replace(recoverTo, getPublicKey(impostor))] : t)) }
    expect(() => requestDetails(tampered)).toThrow(/not a recovery request/)
    expect(() => rel(tampered)).toThrow(/not a recovery request/)
    // Two requests for the same epoch in the same second are distinct elections.
    const twin = await requestRecovery({ keeperPrivateKey: keeper, epochId: EPOCH, members, delaySeconds: DELAY, recoverTo, now: () => now })
    expect(twin.id).not.toBe(genuine.id)
    expect(twin.tags.find((t) => t[0] === 'd')![1]).not.toBe(genuine.tags.find((t) => t[0] === 'd')![1])
    await expect(requestRecovery({ keeperPrivateKey: keeper, epochId: 'a:b', members, delaySeconds: DELAY, recoverTo })).rejects.toThrow(/colon/)
  })
})
