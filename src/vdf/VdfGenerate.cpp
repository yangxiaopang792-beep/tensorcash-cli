// Keep both generation and verification in one TU to avoid
// multiple inclusions of chiavdf C sources (bqfc.c) across objects.

#include "VdfGenerate.h"
#include "VdfVerify.h"

#include <vector>
#include <cstring>
#include <cstdlib>
#include <cfenv>
#include <mutex>
#ifdef _WIN32
#include <malloc.h>
#endif

// chiavdf headers (GMP-based). Include paths are added in CMake.
#include "verifier.h"
#include "prover_slow.h"
#include "create_discriminant.h"

namespace vdf {

namespace {

void* NodeMpAllocFunc(size_t new_bytes)
{
    new_bytes = ((new_bytes + 8) + 15) & ~size_t{15};
#ifdef _WIN32
    auto* ret = static_cast<uint8_t*>(_aligned_malloc(new_bytes, 16));
#else
    void* ptr = nullptr;
    if (::posix_memalign(&ptr, 16, new_bytes) != 0) return nullptr;
    auto* ret = static_cast<uint8_t*>(ptr);
#endif
    return ret + 8;
}

void NodeMpFreeFunc(void* old_ptr, size_t)
{
    if ((std::uintptr_t(old_ptr) & 15) == 8) {
#ifdef _WIN32
        _aligned_free(static_cast<uint8_t*>(old_ptr) - 8);
#else
        std::free(static_cast<uint8_t*>(old_ptr) - 8);
#endif
    } else if ((std::uintptr_t(old_ptr) & 63) != 0) {
        std::free(old_ptr);
    }
}

void* NodeMpReallocFunc(void* old_ptr, size_t old_size, size_t new_bytes)
{
    void* ret = NodeMpAllocFunc(new_bytes);
    ::memcpy(ret, old_ptr, std::min(old_size, new_bytes));
    NodeMpFreeFunc(old_ptr, old_size);
    return ret;
}

void EnsureVdfRuntimeInit()
{
    static std::once_flag init_once;
    std::call_once(init_once, [] {
        mp_set_memory_functions(NodeMpAllocFunc, NodeMpReallocFunc, NodeMpFreeFunc);
        allow_integer_constructor = true;
        // Note: FE_TOWARDZERO is set per-call in VDF functions, not globally,
        // to avoid poisoning the FP rounding mode for the rest of the process
        // (e.g. GetDifficulty relies on default FE_TONEAREST rounding).
    });
}

/// RAII guard that sets FE_TOWARDZERO for the scope and restores on exit.
struct VdfRoundingGuard {
    int prev;
    VdfRoundingGuard() : prev(fegetround()) { fesetround(FE_TOWARDZERO); }
    ~VdfRoundingGuard() { fesetround(prev); }
    VdfRoundingGuard(const VdfRoundingGuard&) = delete;
    VdfRoundingGuard& operator=(const VdfRoundingGuard&) = delete;
};

} // namespace

bool VerifyAgainstPrevHash(const uint256& prev_hash,
                           std::span<const uint8_t> vdf_proof,
                           uint64_t iterations,
                           uint32_t discr_bits,
                           uint32_t recursion)
{
    try {
        EnsureVdfRuntimeInit();
        VdfRoundingGuard rounding_guard;

        if (vdf_proof.data() == nullptr || vdf_proof.size() == 0) return false;

        // Challenge is the previous block hash bytes (32 bytes), as-is.
        std::vector<uint8_t> seed(prev_hash.begin(), prev_hash.end());
        if (seed.size() != 32) return false;

        integer D = CreateDiscriminant(seed, discr_bits);

        // x = form(2,1,D)
        form x = form::from_abd(integer(2), integer(1), D);
        x.reduce();

        const int real_bits = D.num_bits();
        std::vector<uint8_t> x_bytes = SerializeForm(x, real_bits);

        return CheckProofOfTimeNWesolowski(
            D,
            x_bytes.data(),
            vdf_proof.data(),
            static_cast<int32_t>(vdf_proof.size()),
            iterations,
            real_bits,
            static_cast<int32_t>(recursion)
        );
    } catch (...) {
        return false;
    }
}

std::vector<uint8_t> GenerateProofForTesting(const uint256& prev_hash,
                                             uint64_t iterations,
                                             uint32_t discr_bits)
{
    try {
        EnsureVdfRuntimeInit();
        VdfRoundingGuard rounding_guard;

        // Optionally disable ASM paths when using larger discriminants
        if (discr_bits > 1024) {
        #if defined(_WIN32)
            _putenv("CHIAVDF_NO_ASM=1");
        #else
            setenv("CHIAVDF_NO_ASM", "1", 1);
        #endif
        }

        // Challenge is exactly the previous block hash, 32 bytes
        std::vector<uint8_t> seed(prev_hash.begin(), prev_hash.end());
        if (seed.size() != 32) return {};

        integer D = CreateDiscriminant(seed, discr_bits);

        // x = (2,1,D)
        form x = form::from_abd(integer(2), integer(1), D);
        x.reduce();

        // ProveSlow returns y_bytes || proof_bytes matching verifier expectations
        return ProveSlow(D, x, iterations, "");
    } catch (...) {
        return {};
    }
}

void CleanupTestProver()
{
    // No-op for ProveSlow-based tests
}

} // namespace vdf
