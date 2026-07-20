// Tests for proof bucket deduplication key (proof_id) derivation

#include <boost/test/unit_test.hpp>

#include <hash.h>
#include <uint256.h>
#include <span.h>

// Local copy of the leaf hasher used for L_vdf (tag=0x02)
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

BOOST_AUTO_TEST_SUITE(proof_bucket_dedup_tests)

BOOST_AUTO_TEST_CASE(identical_vdf_same_proof_id)
{
    std::vector<unsigned char> vdf{1,2,3,4,5,6,7,8,9,10};
    uint256 a = LeafHash(0x02, vdf);
    uint256 b = LeafHash(0x02, vdf);
    BOOST_CHECK_EQUAL(a.ToString(), b.ToString());
}

BOOST_AUTO_TEST_CASE(different_vdf_different_proof_id)
{
    std::vector<unsigned char> v1{1,2,3,4,5};
    std::vector<unsigned char> v2{1,2,3,4,6};
    uint256 a = LeafHash(0x02, v1);
    uint256 b = LeafHash(0x02, v2);
    BOOST_CHECK(a != b);
}

BOOST_AUTO_TEST_SUITE_END()

