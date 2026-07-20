// Approximate memory footprint for sidecars and branches.

#include <bench/bench.h>
#include <uint256.h>
#include <random>

static void SidecarMemoryUsage(benchmark::Bench& bench)
{
    const size_t N = 100000; // number of sidecars
    std::mt19937_64 rng(12345);
    std::vector<std::vector<unsigned char>> vdfs;
    std::vector<std::vector<uint256>> branches_tick;
    std::vector<std::vector<uint256>> branches_vdf;
    vdfs.reserve(N); branches_tick.reserve(N); branches_vdf.reserve(N);

    bench.minEpochIterations(1).run([&] {
        vdfs.clear(); branches_tick.clear(); branches_vdf.clear();
        for (size_t i = 0; i < N; ++i) {
            // vdf ~200 bytes
            std::vector<unsigned char> v(200);
            for (auto& b : v) b = static_cast<unsigned char>(rng());
            vdfs.emplace_back(std::move(v));
            // two-level branches (2 hashes each)
            uint256 h1, h2, h3, h4;
            for (size_t j = 0; j < 32; ++j) h1.data()[j] = static_cast<unsigned char>(rng());
            for (size_t j = 0; j < 32; ++j) h2.data()[j] = static_cast<unsigned char>(rng());
            for (size_t j = 0; j < 32; ++j) h3.data()[j] = static_cast<unsigned char>(rng());
            for (size_t j = 0; j < 32; ++j) h4.data()[j] = static_cast<unsigned char>(rng());
            std::vector<uint256> tick_hashes; tick_hashes.push_back(h1); tick_hashes.push_back(h2);
            std::vector<uint256> vdf_hashes; vdf_hashes.push_back(h3); vdf_hashes.push_back(h4);
            branches_tick.emplace_back(std::move(tick_hashes));
            branches_vdf.emplace_back(std::move(vdf_hashes));
        }
        // report approx memory
        size_t bytes = 0;
        for (const auto& v : vdfs) bytes += v.size();
        bytes += branches_tick.size() * 2 * sizeof(uint256);
        bytes += branches_vdf.size() * 2 * sizeof(uint256);
        bench.complexityN(bytes);
    });
}

BENCHMARK(SidecarMemoryUsage, benchmark::PriorityLevel::LOW);

