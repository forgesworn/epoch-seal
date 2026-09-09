import { describe, it, expect } from 'vitest'
import { finalizeEvent, generateSecretKey, getPublicKey } from 'nostr-tools/pure'
import type { NostrEvent } from 'nostr-tools/pure'
import { sealEpoch, openShare, recoverEpoch, requestRecovery, recoveryOutcome, requestDetails, releaseShare, PoisonedShareError } from '../src/index.js'

function rng(seed: number) { let s = seed >>> 0; return () => { s = (s * 1664525 + 1013904223) >>> 0; return s / 0x100000000 } }
function flipString(s: string, r: () => number): string { const i = Math.floor(r() * s.length); return s.slice(0, i) + String.fromCharCode(s.charCodeAt(i) ^ 1) + s.slice(i + 1) }
const keeper = generateSecretKey()
const circle = Array.from({ length: 5 }, () => generateSecretKey())
const members = circle.map(getPublicKey)
const epochKey = new Uint8Array(32).map((_, i) => (i * 7 + 3) & 0xff)
const N = 400

describe('fuzz: shares', () => {
  const sealed = sealEpoch({ epochKey, epochId: 'e1', keeperPrivateKey: keeper, members, threshold: 3, delaySeconds: 3600 }).shares
  it('a mutated wrap never opens and never hangs', () => {
    const r = rng(31)
    for (let i = 0; i < N; i++) {
      const s = sealed[Math.floor(r() * sealed.length)]!
      const m: NostrEvent = { ...s.wrap, tags: s.wrap.tags.map((t) => [...t]) }
      const op = Math.floor(r() * 3)
      if (op === 0) m.content = flipString(m.content, r)
      else if (op === 1) m.pubkey = flipString(m.pubkey, r)
      else m.content = m.content.slice(0, Math.floor(r() * m.content.length))
      let threw = false
      try { openShare(m, circle[members.indexOf(s.member)]!) } catch (e) { threw = e instanceof Error }
      expect(threw).toBe(true)
    }
  })
  it('random share sets never reconstruct the key by accident', () => {
    const r = rng(32)
    const opened = sealed.map((s) => openShare(s.wrap, circle[members.indexOf(s.member)]!))
    for (let i = 0; i < 200; i++) {
      const bad = opened.slice(0, 3).map((o) => ({ ...o, data: new Uint8Array(o.data).map((b) => (r() < 0.1 ? b ^ 1 : b)) }))
      const untouched = bad.every((b, j) => Buffer.from(b.data).equals(Buffer.from(opened[j]!.data)))
      let out: Uint8Array | undefined, err: unknown
      try { out = recoverEpoch(bad) } catch (e) { err = e }
      // A touched share is caught by its commitment and named; an untouched set rebuilds the key.
      if (untouched) expect(Buffer.from(out!).equals(Buffer.from(epochKey))).toBe(true)
      else {
        expect(err).toBeInstanceOf(PoisonedShareError)
        expect(bad.some((b, j) => b.index === (err as PoisonedShareError).index && !Buffer.from(b.data).equals(Buffer.from(opened[j]!.data)))).toBe(true)
      }
    }
    expect(() => recoverEpoch([opened[0]!, { ...opened[1]!, epochId: 'other' }, opened[2]!])).toThrow(/one sealing/)
  })
})

describe('fuzz: recovery', () => {
  it('garbage requests and ballots never release a share', async () => {
    const r = rng(33)
    const sealed = sealEpoch({ epochKey, epochId: 'e2', keeperPrivateKey: keeper, members, threshold: 3, delaySeconds: 3600 }).shares
    const share = openShare(sealed[0]!.wrap, circle[members.indexOf(sealed[0]!.member)]!)
    const later = Math.floor(Date.now() / 1000) + 3602
    for (let i = 0; i < 200; i++) {
      const junk = finalizeEvent({ kind: r() < 0.5 ? 30482 : Math.floor(r() * 40000), created_at: Math.floor(Date.now() / 1000), tags: [['d', 'unseal:e2:1'], ['title', 'x'], ['closes', String(Math.floor(r() * 2e9))]], content: 'garbage' }, generateSecretKey())
      expect(() => requestDetails(junk)).toThrow()
      expect(() => releaseShare({ memberPrivateKey: circle[members.indexOf(sealed[0]!.member)]!, share, request: junk, ballots: [], members, firstSeen: 1, now: later })).toThrow()
    }
    const request = await requestRecovery({ keeperPrivateKey: keeper, epochId: 'e2', members, delaySeconds: 3600, recoverTo: getPublicKey(generateSecretKey()), now: () => later - 3601 })
    for (let i = 0; i < 200; i++) {
      const fake = finalizeEvent({ kind: 30483, created_at: Math.floor(Date.now() / 1000), tags: [['election', request.id], ['key-image', 'ab'.repeat(32)], ['ring-sig', 'cd'.repeat(64)]], content: 'x' }, generateSecretKey())
      let out
      expect(() => { out = recoveryOutcome(request, [fake], members, later) }).not.toThrow()
      expect(out).toBe('allowed')   // a forged ballot is not a refusal
    }
  })
})
