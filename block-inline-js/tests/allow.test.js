import { test } from "node:test";
import assert from "node:assert/strict";

import {
  ALLOWED_HASH_RE,
  CONTAINER_DIGEST_RE,
  canonicalAllowKey,
  normalizeInlineHash,
} from "../lib/allow.js";

const HASH = "sha256-ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/=";
const HEX = "a".repeat(64);

test("ALLOWED_HASH_RE: accepts valid sha256 tokens, rejects prefixes and junk", () => {
  assert.equal(ALLOWED_HASH_RE.test(HASH), true);
  assert.equal(ALLOWED_HASH_RE.test(`attr-${HASH}`), false);
  assert.equal(ALLOWED_HASH_RE.test(HEX), false);
  assert.equal(ALLOWED_HASH_RE.test("sha256-abc"), false);
  assert.equal(ALLOWED_HASH_RE.test("SHA-256-abcdef"), false);
});

test("CONTAINER_DIGEST_RE: 64 lowercase hex, nothing else", () => {
  assert.equal(CONTAINER_DIGEST_RE.test(HEX), true);
  assert.equal(CONTAINER_DIGEST_RE.test(HEX.toUpperCase()), false);
  assert.equal(CONTAINER_DIGEST_RE.test(`${HEX}0`), false);
  assert.equal(CONTAINER_DIGEST_RE.test(`attr-${HEX}`), false);
});

test("normalizeInlineHash accepts plain and attr-prefixed tokens", () => {
  assert.equal(normalizeInlineHash(HASH), HASH);
  assert.equal(normalizeInlineHash(`attr-${HASH}`), HASH);
});

test("normalizeInlineHash rejects anything no CSP hash could be", () => {
  assert.throws(() => normalizeInlineHash(HASH.slice(7)), /invalid sha256/);
  assert.throws(() => normalizeInlineHash(HEX), /invalid sha256/);
  assert.throws(() => normalizeInlineHash(""), /invalid sha256/);
  assert.throws(() => normalizeInlineHash(null), /invalid sha256/);
});

test("canonicalAllowKey strips only the handler attr- prefix", () => {
  assert.equal(canonicalAllowKey(`attr-${HASH}`), HASH);
  assert.equal(canonicalAllowKey(HASH), HASH);
  assert.equal(canonicalAllowKey(HEX), HEX);
  assert.equal(canonicalAllowKey("https://cdn.example.com"), "https://cdn.example.com");
  assert.equal(canonicalAllowKey(null), "");
  assert.equal(canonicalAllowKey(undefined), "");
});