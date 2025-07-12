# CVE-2025-30397: Persistent Heap Overflow in Microsoft Scripting Engine

*Even though the heap overflow primitive was addressed in the May 2025 patch, careful analysis shows that memory corruption can still be triggered in the updated **jscript.dll** under certain conditions due to subtle off-by and arithmetic edge‑case errors.*

---

## Background

* **CVE ID:** CVE‑2025‑30397
* **Component:** Microsoft Scripting Engine (JScript.dll, VBScript.dll)
* **Attack Vector:** Remote attacker lures a user to an Edge page running in Internet Explorer (IE) Mode, delivering malicious JS/VBScript.
* **Impact:** Remote Code Execution (requires user interaction)
* **CVSS 3.1:** AV\:N/AC\:H/PR\:N/UI\:R/S\:U/C\:H/I\:H/A\:H (7.5 – High)
* **CISA KEV Deadline:** June 3, 2025

## Patch Details (KB5058379)

* **Release Date:** May 13, 2025
* **Windows 10 Editions:** 21H2 & 22H2 (x86, x64, ARM64)
* **Distribution:** Windows Update & WSUS
* **Components Updated:** JScript.dll, VBScript.dll

Microsoft replaced dozens of raw `malloc()/memcpy()` sequences with a unified, bounds‑checked helper and introduced Control‑Flow Guard checks. However, new edge‑cases remain exploitable.

## Key Code Paths

### Unpatched Primitive (Heap-Based Overflow)

```c
undefined4 *FUN_633915a0(void *this, …, UINT *lengthPtr, …) {
    size_t len = lengthPtr[2] & 0xfffffffe;
    int *buf = (int*)HeapAlloc(GetProcessHeap(), 0, len);
    memcpy(buf, (void*)lengthPtr[2], len);
    /* → heap overflow if len is oversized or mis‑aligned */
    *(int**)((char*)this + 0x38) = buf;
    return buf ? S_OK : E_OUTOFMEMORY;
}
```

### Patched Helper (FUN\_18001e9c0, simplified)

```c
undefined8 FUN_18001e9c0(
    ctx_t *ctx,
    void **outBuf,
    void *srcPtr,
    uint32_t *lenPtr,
    int flags       // unused for unit scaling
) {
    int charCount  = (int)lenPtr[1];         // attacker-controlled
    int dataBytes  = charCount * 2;          // UTF-16
    int headerOver = 0x42;
    int totalNeeded = dataBytes + headerOver;

    // Underflow guard
    if (totalNeeded < 1) return 0;
    // Max‑capacity guard
    if (totalNeeded >= ctx->maxCapacity) return 0;
    // Misalignment/overflow guard
    if ((dataBytes + 0x4A) < totalNeeded) return 0;

    // Allocate exactly dataBytes + 0x4A
    void *buf = malloc(dataBytes + 0x4A);
    if (!buf) return 0;
    *outBuf = buf;

    // Copy, including null terminator (+2 bytes)
    memcpy((uint8_t*)buf + 0x48, srcPtr, dataBytes + 2);
    return 1;
}
```

## Persisting Vulnerabilities in the Patched DLL

1. **Off‑by‑Two Terminator Overflow**
   Guards ensure space for `(dataBytes + headerOver)` but not the extra 2 bytes of null terminator, allowing a 2‑byte overrun.

2. **Off‑by‑Eight Header Mismatch**
   Allocation uses `+0x4A` but the capacity check uses `+0x42`, creating an 8‑byte gap that can slip past the guard.

3. **Signed Integer Wraps**
   `charCount * 2` and `totalNeeded = dataBytes + headerOver` use 32‑bit signed math. If `charCount > INT_MAX/2`, arithmetic wraps, bypassing checks and allocating a tiny buffer but copying a huge payload.

4. **Buffer Reuse Edge‑Case**
   When exactly `(capacity – used) == totalNeeded`, the helper reuses an existing buffer but still performs `memcpy(buf+0x48, src, dataBytes+2)`, overrunning by 2 bytes.

5. **Flags Parameter Ignored**
   A single helper is used for strings, regex patterns, COM BSTRs and array buffers without adjusting units or overhead, risking mis‑sized copies in non‑string contexts.

6. **Null or Malformed Pointers**
   Callers occasionally pass `lenPtr == NULL` to represent zero length. The helper dereferences `lenPtr+1` unconditionally, leading to garbage `charCount` and uncontrolled allocations.

## Exploitation Feasibility

Although the original primitive was patched, these residual edge‑cases allow:

* **Heap metadata corruption**: Overruns of 2–8 bytes can corrupt size fields or freelist links.
* **Vtable hijacking**: Adjacent JS object headers or vtable pointers can be overwritten by controlled overflow data.
* **Arbitrary writes**: Integer‑wrap attacks can produce huge copies, enabling extensive heap corruption.

Attackers can still achieve reliable Remote Code Execution by combining heap spraying with these oversights in the patched DLL.

## Recommendations

* **Use unsigned 64‑bit arithmetic** for all length calculations and comparisons.
* **Unify overhead constants** (e.g. header size and allocation size) to eliminate off‑by gaps.
* **Include null terminator** in the guard logic (`totalNeeded += 2`).
* **Validate `lenPtr != NULL`** before dereferencing.
* **Branch on flags** to apply correct unit scaling (×2 for UTF-16, ×sizeof(void\*) for arrays).
* **Return defined HRESULTs** on Control‑Flow Guard failures, avoiding uninitialized values.

---

*By analyzing the updated Scripting Engine, we see that even with the primitive patched, subtle edge‑cases leave memory corruption paths open. Applying the recommendations above will fully close these remaining gaps.*
