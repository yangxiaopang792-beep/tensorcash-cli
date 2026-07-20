// Rough presync load benchmark: build synthetic HEADERS_EXT-like data and compute leaf hashes.

#include <bench/bench.h>
#include <hash.h>
#include <uint256.h>
#include <span.h>
#include <vector>

static uint256 LeafHash(uint8_t tag, std::span<const unsigned char> data)
{
    CHash256 h;
    const unsigned char prefix[6] = {0xff, 'P','O','W','\0', tag};
    h.Write(prefix);
    uint32_t len = (uint32_t)data.size();
    unsigned char lbuf[4];
    WriteLE32(lbuf, len);
    h.Write(lbuf);
    if (len) h.Write(data);
    uint256 out; h.Finalize(out); return out;
}

static void PresyncLeafHashLoad(benchmark::Bench& bench)
{
    const size_t N = 50000; // synthetic sidecars per epoch
    std::vector<std::vector<unsigned char>> vdfs(N, std::vector<unsigned char>(200, 0x42));
    std::vector<uint64_t> ticks(N, 1000);
    std::vector<uint256> out_ltick(N), out_lvdf(N);

    bench.minEpochIterations(1).run([&] {
        for (size_t i = 0; i < N; ++i) {
            unsigned char tbuf[8]; WriteLE64(tbuf, ticks[i]);
            out_ltick[i] = LeafHash(0x01, std::span<const unsigned char>(tbuf, sizeof(tbuf)));
            out_lvdf[i] = LeafHash(0x02, vdfs[i]);
        }
    });
}

BENCHMARK(PresyncLeafHashLoad, benchmark::PriorityLevel::LOW);

