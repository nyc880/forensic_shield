// ============================================================================
// native-lib.cpp — page-dedicated locked-memory arena for the CVLT engine
// Location: app/src/main/cpp/native-lib.cpp
//
// JNI target class : com.example.lock.enc.NativeMemoryManager
// Symbol names MUST match the Kotlin package exactly, otherwise every native
// call fails with UnsatisfiedLinkError at first invocation.
//
// Step-6 redesign — why an arena instead of per-allocation mlock:
//   The previous design did posix_memalign + mlock(ptr, size) per secret and
//   munlock(ptr, size) on free. mlock/munlock operate at PAGE granularity:
//     - several 32–48 B secrets share one page, so munlock on one secret
//       unlocked the WHOLE page, momentarily exposing other live secrets on
//       that page to swap/dump;
//     - mlock on one secret also pinned unrelated data sharing the page;
//     - RLIMIT_MEMLOCK was consumed per allocation, so failure was
//       unpredictable under memory pressure.
//   The fix: ONE dedicated anonymous mmap region, locked ONCE in full with a
//   single mlock, marked MADV_DONTDUMP, with secrets sub-allocated inside.
//   Pages now contain ONLY engine secrets, are never individually unlocked,
//   and the RLIMIT cost is fixed and known (kArenaBytes).
//
// Failure policy (deliberate, fail-closed):
//   The arena size ladder (32/16/8 KiB) is tried at first allocation. If
//   mmap or mlock fails for EVERY size (e.g. RLIMIT_MEMLOCK far below any
//   candidate on a constrained device), the arena is marked dead and every
//   allocation returns 0. Kotlin's NativeMemoryManager then reports the
//   native layer unavailable and the KDF refuses to derive keys rather than
//   silently keeping them in swappable memory. Decision per external review:
//   REJECT, never warn-and-continue — a security-first app must not hold
//   keys in pageable memory. MUST still be verified on real low-end devices
//   during QA; if a target fleet rejects even 8 KiB of locked memory, that
//   fleet cannot run this engine at all (surfaced at startup, not mid-op).
//
// Other hardening (unchanged from the previous revision):
//   - Allocation registry: addresses are validated BEFORE any dereference;
//     garbage/stale pointers are rejected without segfault.
//   - Per-slot header with magic + recorded size; every copy is
//     bounds-checked (native heap overflow guard).
//   - Slots are zeroized on allocate AND on free (payload + header).
//   - GetPrimitiveArrayCritical for array access: no transient JVM-heap
//     copies of key material.
//   - Startup self-test (nativeSelfTest) exercises positive and negative
//     paths so linkage/ABI/RLIMIT problems fail fast at library load.
// ============================================================================

#include <jni.h>
#include <sys/mman.h>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <vector>

#ifndef MADV_DONTDUMP
// Linux asm-generic/mman-common.h: MADV_DONTDUMP == 16.
// (24 is MADV_DONTNEED_LOCKED on kernel >= 5.18 — it would DISCARD locked
// pages, which is the opposite of what we want. NDK headers normally define
// MADV_DONTDUMP, so this fallback rarely activates.)
#define MADV_DONTDUMP 16
#endif

namespace {

constexpr uint64_t kAllocMagic    = 0x43564C545F4D454DULL; // "CVLT_MEM"
constexpr size_t   kHeaderBytes   = 16;                    // magic(8) + size(8)
constexpr size_t   kAlignment     = 16;
constexpr size_t   kMaxSlotBytes  = 4096;                  // sanity cap per secret
constexpr size_t   kMaxAllocCount = 512;                   // live-slot cap
constexpr size_t   kMinFreeBlock  = 32;                    // don't split into dust

// Arena size ladder, tried in order at first allocation. mlock is subject
// to RLIMIT_MEMLOCK, which differs between devices (sometimes as low as a
// few tens of KiB). Secrets are small (32–48 B keys), so even the smallest
// arena holds ~100 slots. If EVERY size is rejected the native layer is
// marked unavailable and the whole engine fails CLOSED — keys are never
// silently kept in swappable memory (see failure policy in the header).
// QA note: this ladder still needs verification on real low-end devices.
const size_t kArenaSizeLadder[] = {32 * 1024, 16 * 1024, 8 * 1024};

struct SlotHeader {
    uint64_t magic;
    uint64_t size; // usable payload bytes located after this header
};

struct LiveSlot {
    void*  user;      // arena + offset + kHeaderBytes (value handed to Java)
    size_t offset;    // slot start (header) relative to arena base
    size_t userSize;  // payload size in bytes
    size_t slotBytes; // full region consumed (incl. absorbed dust tail)
};

struct FreeBlock {
    size_t offset; // relative to arena base, header space included
    size_t size;   // total usable bytes in this free block
};

std::mutex               g_mutex;
unsigned char*           g_arena     = nullptr;
size_t                   g_arenaSize = 0;
bool                     g_arenaDead = false; // all ladder sizes failed: fail closed forever
std::vector<LiveSlot>    g_live;
std::vector<FreeBlock>   g_free;

/**
 * Zeroization that the optimizer must not remove.
 * The volatile pointer forces every store to be emitted.
 */
void secureZero(void* ptr, size_t len) {
    if (ptr == nullptr || len == 0) return;
    volatile unsigned char* p = static_cast<volatile unsigned char*>(ptr);
    while (len--) {
        *p++ = 0;
    }
}

size_t alignUp(size_t v, size_t a) {
    return (v + a - 1) & ~(a - 1);
}

/** Lazily creates and locks the arena. Caller MUST hold g_mutex. */
bool ensureArenaLocked() {
    if (g_arenaDead) return false;
    if (g_arena != nullptr) return true;

    // Try the size ladder from largest to smallest: a constrained
    // RLIMIT_MEMLOCK may reject 32 KiB but accept 8 KiB.
    for (const size_t candidate : kArenaSizeLadder) {
        void* p = mmap(nullptr, candidate, PROT_READ | PROT_WRITE,
                       MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
        if (p == MAP_FAILED) continue;

        // One single mlock for the whole arena: pages contain only our
        // secrets, and no per-secret unlock can ever expose a neighbour.
        if (mlock(p, candidate) != 0) {
            munmap(p, candidate);
            continue; // try a smaller arena
        }

        // Best-effort: keep the arena out of core dumps / crash dumps.
        madvise(p, candidate, MADV_DONTDUMP);

        secureZero(p, candidate); // never hand out dirty pages

        g_arena     = static_cast<unsigned char*>(p);
        g_arenaSize = candidate;
        g_free.clear();
        g_free.push_back(FreeBlock{0, candidate});
        return true;
    }

    g_arenaDead = true; // every size rejected: fail closed, never retry
    return false;
}

/** Registry lookup by user pointer. Caller MUST hold g_mutex. */
const LiveSlot* findSlotLocked(void* userPtr) {
    for (const auto& s : g_live) {
        if (s.user == userPtr) return &s;
    }
    return nullptr;
}

/** Coalescing insertion into the free list (keeps it sorted by offset). */
void releaseBlockLocked(size_t offset, size_t size) {
    FreeBlock block{offset, size};
    size_t pos = 0;
    while (pos < g_free.size() && g_free[pos].offset < block.offset) ++pos;
    g_free.insert(g_free.begin() + static_cast<long>(pos), block);

    // Merge with the next block, then with the previous block.
    for (int pass = 0; pass < 2; ++pass) {
        for (size_t i = 0; i + 1 < g_free.size();) {
            FreeBlock& a = g_free[i];
            FreeBlock& b = g_free[i + 1];
            if (a.offset + a.size == b.offset) {
                a.size += b.size;
                g_free.erase(g_free.begin() + static_cast<long>(i) + 1);
            } else {
                ++i;
            }
        }
    }
}

jlong doAllocate(jlong size) {
    if (size <= 0 || size > static_cast<jlong>(kMaxSlotBytes)) return 0;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (!ensureArenaLocked()) return 0;
    if (g_live.size() >= kMaxAllocCount) return 0;

    const size_t userSize = static_cast<size_t>(size);
    const size_t total    = kHeaderBytes + alignUp(userSize, kAlignment);

    // First-fit over the free list.
    for (size_t i = 0; i < g_free.size(); ++i) {
        FreeBlock& blk = g_free[i];
        if (blk.size < total) continue;

        const size_t slotOffset = blk.offset;
        const size_t remainder  = blk.size - total;

        // Consumed region: normally 'total', but a tiny unsplittable tail is
        // absorbed into this slot so free() can return the exact region —
        // otherwise those bytes would leak and break coalescing.
        size_t consumed = total;

        if (remainder >= kMinFreeBlock) {
            blk.offset += total;
            blk.size    = remainder;
        } else {
            consumed += remainder;
            g_free.erase(g_free.begin() + static_cast<long>(i));
        }

        auto* hdr = reinterpret_cast<SlotHeader*>(g_arena + slotOffset);
        hdr->magic = kAllocMagic;
        hdr->size  = userSize;

        unsigned char* user = g_arena + slotOffset + kHeaderBytes;
        secureZero(user, userSize);

        g_live.push_back(LiveSlot{user, slotOffset, userSize, consumed});
        return static_cast<jlong>(reinterpret_cast<uintptr_t>(user));
    }

    return 0; // arena full: fail closed
}

jboolean doFree(jlong address, jlong size) {
    if (address == 0 || size <= 0) return JNI_FALSE;

    std::lock_guard<std::mutex> lock(g_mutex);
    if (g_arena == nullptr) return JNI_FALSE;

    auto* userPtr = reinterpret_cast<unsigned char*>(static_cast<uintptr_t>(address));

    // Range check BEFORE any dereference: reject pointers outside the arena.
    if (userPtr < g_arena + kHeaderBytes || userPtr >= g_arena + g_arenaSize) {
        return JNI_FALSE;
    }

    const LiveSlot* found = nullptr;
    size_t foundIndex = 0;
    for (size_t i = 0; i < g_live.size(); ++i) {
        if (g_live[i].user == userPtr) {
            found = &g_live[i];
            foundIndex = i;
            break;
        }
    }
    if (found == nullptr) return JNI_FALSE;                              // unknown / already freed
    if (static_cast<uint64_t>(size) != found->userSize) return JNI_FALSE; // caller size mismatch

    auto* hdr = reinterpret_cast<SlotHeader*>(g_arena + found->offset);
    if (hdr->magic != kAllocMagic) return JNI_FALSE;                     // corrupted header

    const size_t slotOffset = found->offset;
    const size_t total      = found->slotBytes; // exact region consumed at allocate

    secureZero(userPtr, found->userSize);  // payload
    secureZero(hdr, kHeaderBytes);         // header (kills magic -> double-free trap)

    g_live.erase(g_live.begin() + static_cast<long>(foundIndex));
    releaseBlockLocked(slotOffset, total);
    return JNI_TRUE;
    // NOTE: no munlock here, by design. The arena pages stay locked until
    // process death; unlocking per slot would expose sibling secrets on the
    // same page (the exact flaw of the previous design).
}

jboolean doCopyFromJava(JNIEnv* env, jbyteArray src, jlong destAddress, jint length) {
    if (src == nullptr || length <= 0 || destAddress == 0) return JNI_FALSE;

    const jsize arrLen = env->GetArrayLength(src);
    if (length > arrLen) return JNI_FALSE;

    std::lock_guard<std::mutex> lock(g_mutex);
    auto* userPtr = reinterpret_cast<void*>(static_cast<uintptr_t>(destAddress));
    const LiveSlot* s = findSlotLocked(userPtr);
    if (s == nullptr) return JNI_FALSE;                                 // invalid address
    if (static_cast<uint64_t>(length) > s->userSize) return JNI_FALSE;  // overflow guard

    // Critical section: short memcpy only, no other JNI calls, no blocking.
    jbyte* srcBytes = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(src, nullptr));
    if (srcBytes == nullptr) return JNI_FALSE;
    memcpy(userPtr, srcBytes, static_cast<size_t>(length));
    env->ReleasePrimitiveArrayCritical(src, srcBytes, JNI_ABORT); // read-only source: discard
    return JNI_TRUE;
}

jboolean doCopyToJava(JNIEnv* env, jlong srcAddress, jbyteArray dest, jint length) {
    if (dest == nullptr || length <= 0 || srcAddress == 0) return JNI_FALSE;

    const jsize arrLen = env->GetArrayLength(dest);
    if (length > arrLen) return JNI_FALSE;

    std::lock_guard<std::mutex> lock(g_mutex);
    auto* userPtr = reinterpret_cast<void*>(static_cast<uintptr_t>(srcAddress));
    const LiveSlot* s = findSlotLocked(userPtr);
    if (s == nullptr) return JNI_FALSE;                                 // invalid address
    if (static_cast<uint64_t>(length) > s->userSize) return JNI_FALSE;  // over-read guard

    jbyte* destBytes = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(dest, nullptr));
    if (destBytes == nullptr) return JNI_FALSE;
    memcpy(destBytes, userPtr, static_cast<size_t>(length));
    env->ReleasePrimitiveArrayCritical(dest, destBytes, 0); // mode 0: commit changes
    return JNI_TRUE;
}

void doWipeJavaArray(JNIEnv* env, jbyteArray array) {
    if (array == nullptr) return;
    const jsize len = env->GetArrayLength(array);
    if (len <= 0) return;

    jbyte* bytes = static_cast<jbyte*>(env->GetPrimitiveArrayCritical(array, nullptr));
    if (bytes != nullptr) {
        secureZero(bytes, static_cast<size_t>(len));
        env->ReleasePrimitiveArrayCritical(array, bytes, 0); // commit zeros even if a copy was made
    }
}

} // namespace

extern "C" {

JNIEXPORT jlong JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeAllocateLocked(
        JNIEnv* /*env*/, jobject /*thiz*/, jlong size) {
    return doAllocate(size);
}

JNIEXPORT jboolean JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeFreeLocked(
        JNIEnv* /*env*/, jobject /*thiz*/, jlong address, jlong size) {
    return doFree(address, size);
}

JNIEXPORT jboolean JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeCopyFromByteArray(
        JNIEnv* env, jobject /*thiz*/, jbyteArray src, jlong destAddress, jint length) {
    return doCopyFromJava(env, src, destAddress, length);
}

JNIEXPORT jboolean JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeCopyToByteArray(
        JNIEnv* env, jobject /*thiz*/, jlong srcAddress, jbyteArray dest, jint length) {
    return doCopyToJava(env, srcAddress, dest, length);
}

JNIEXPORT void JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeWipeByteArray(
        JNIEnv* env, jobject /*thiz*/, jbyteArray array) {
    doWipeJavaArray(env, array);
}

JNIEXPORT jboolean JNICALL
Java_com_example_lock_enc_NativeMemoryManager_nativeSelfTest(
        JNIEnv* env, jobject /*thiz*/) {
    // Exercises: arena init -> allocate -> copy-in -> copy-out -> compare ->
    // wipe -> free, plus negative paths: oversized copy rejection and
    // double-free rejection. Any failure marks the native layer unavailable
    // (fail-closed at startup — also surfaces RLIMIT_MEMLOCK problems).

    constexpr jint N = 32;
    jbyte pattern[N];
    for (jint i = 0; i < N; ++i) {
        pattern[i] = static_cast<jbyte>(0xA5 ^ i);
    }

    jbyteArray arrA = env->NewByteArray(N);
    jbyteArray arrB = env->NewByteArray(N);
    if (arrA == nullptr || arrB == nullptr) {
        if (arrA != nullptr) env->DeleteLocalRef(arrA);
        if (arrB != nullptr) env->DeleteLocalRef(arrB);
        return JNI_FALSE;
    }
    env->SetByteArrayRegion(arrA, 0, N, pattern);

    jboolean ok = JNI_TRUE;

    // 1. Positive round-trip.
    jlong addr = doAllocate(N);
    if (addr == 0) ok = JNI_FALSE;

    if (ok) ok = doCopyFromJava(env, arrA, addr, N);

    if (ok) {
        jbyte zeros[N];
        memset(zeros, 0, sizeof(zeros));
        env->SetByteArrayRegion(arrB, 0, N, zeros);
        ok = doCopyToJava(env, addr, arrB, N);
    }

    if (ok) {
        jbyte out[N];
        memset(out, 0, sizeof(out));
        env->GetByteArrayRegion(arrB, 0, N, out);
        ok = (memcmp(out, pattern, sizeof(pattern)) == 0) ? JNI_TRUE : JNI_FALSE;
    }

    // 2. Negative: a copy larger than the allocation MUST be rejected.
    if (ok) {
        jlong small = doAllocate(16);
        if (small == 0) {
            ok = JNI_FALSE;
        } else {
            if (doCopyFromJava(env, arrA, small, N)) ok = JNI_FALSE; // must fail
            if (!doFree(small, 16)) ok = JNI_FALSE;
        }
    }

    // 3. Wipe path must zero the JVM array.
    if (ok) {
        doWipeJavaArray(env, arrA);
        jbyte out[N];
        memset(out, 1, sizeof(out));
        env->GetByteArrayRegion(arrA, 0, N, out);
        for (jint i = 0; i < N; ++i) {
            if (out[i] != 0) {
                ok = JNI_FALSE;
                break;
            }
        }
    }

    // 4. Free must succeed once, and a double free MUST be rejected.
    if (ok) {
        if (!doFree(addr, N)) {
            ok = JNI_FALSE;
        } else if (doFree(addr, N)) {
            ok = JNI_FALSE;
        }
    }

    env->DeleteLocalRef(arrA);
    env->DeleteLocalRef(arrB);
    return ok;
}

} // extern "C"
