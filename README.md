# tea-napi

# Introduction
Tiny Encryption Algorithm (TEA) for Node.js, in N-API.

Numbers in javascript were signed 32bit integers when doing bit-wise operation.

It's a pain to implement the TEA algorighm in pure javascript, and inefficient too.

So I basically copied the C code from Wikipedia and made it a N-API lib.

It does a IN-PLACE encryption/decryption on the Buffer passed in.


# Padding 

The last several bytes is left untouched if the Buffer was not aligned to TEA_BLOCK_LEN.


# Usage

```typescript
import { teaEncrypt, teaDecrypt, TEA_BLOCK_LEN, TEA_KEY_LEN } from 'tea-napi';

// Default to 32 cycles.
const ITER = 32;

const data = Buffer.alloc(TEA_BLOCK_LEN + 1);

const key = Buffer.alloc(TEA_KEY_LEN);

const encrypted = teaEncrypt(data, key, ITER);

// Same reference, but actually bytes changed.
assert(encrypted === data);

// The last byte, which is not aligned, was left untouched
assert(encrypted[TEA_BLOCK_LEN + 1] === 0);

const decrypted = teaDecrypt(encrypted, key, ITER);

assert(Buffer.compare(decrypted, Buffer.alloc(TEA_BLOCK_LEN + 1)) === 0);

```


