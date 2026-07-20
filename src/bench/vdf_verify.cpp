// Benchmark VDF verification throughput using a known-good vector.

#include <bench/bench.h>
#include <vdf/VdfVerify.h>
#include <uint256.h>
#include <util/strencodings.h>

static std::vector<uint8_t> HexToBytes(const std::string& hex)
{
    return ParseHex<uint8_t>(hex);
}

static void VdfVerifyThroughput(benchmark::Bench& bench)
{
    uint256 prev_hash{uint256()}; // 32 zero bytes
    const std::string vdf_hex =
        "03006acd37874ed54b59686341ea45a6cc7f08c58977de1664f90f85bff42924"
        "af2cd7e16ba13e8e52391a4462cdd399a670d3f06227afe255f4cf81d15ce58"
        "1340e7bcb85ea48b7cf4fc9266af725f21d85f58b281fc1d680e53d44b4b1ff"
        "2ea006010002000f31c61d60d93b930db712135c7980b4c9bc9c4a7a6ebfe11"
        "302eb01fe600025ac46c2e63c3bb0e8271f13cbe25c45a754a9dd897bcf165"
        "de172448a3d1f132f661bef57df7bb94ee5f26c7a44c4bfcf64dcd80eb31cb"
        "dd6aaa12a5083b9454a0100";
    const uint64_t tick = 1998848ULL;
    auto proof = HexToBytes(vdf_hex);

    bench.minEpochIterations(10).run([&] {
        const bool ok = vdf::VerifyAgainstPrevHash(prev_hash, proof, tick, /*discr_bits=*/1024, /*rec=*/0);
        assert(ok);
    });
}

BENCHMARK(VdfVerifyThroughput, benchmark::PriorityLevel::HIGH);

