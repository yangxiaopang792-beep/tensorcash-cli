#!/usr/bin/env python3
# Authoritative generator for the pure-hash + sink layers of OPTION_SERIES_FREEZE.md v1.
# No C++ / EC-library dependency: descriptor (concatenation), asset_id/salts (BIP340 tagged
# SHA256), sink validity (secp256k1 field QR test). Deterministic from the fixed inputs below.
import hashlib, struct

def sha256(b): return hashlib.sha256(b).digest()
def tagged(tag, data):
    t = sha256(tag.encode())
    return sha256(t + t + data)

# secp256k1 field
P = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F
def x_only_valid(x):
    if not (1 <= x < P): return False
    rhs = (pow(x, 3, P) + 7) % P
    return pow(rhs, (P - 1) // 2, P) == 1   # x^3+7 is a quadratic residue -> liftable

def le32(n): return struct.pack('<I', n)
def le64(n): return struct.pack('<Q', n)

# --- Fixed example inputs (frozen test series) ---
descriptor_version = 1
issuance_mode      = 0            # self-issuance
leaf_set           = 1           # D1-b
writer_key = bytes.fromhex('79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798')  # secp G.x (valid x-only)
strike_nbits       = 0x1d00ffff
fixing_height      = 150000
settle_lock_height = 150100
lambda_q           = 218453      # Q16, from OPTION_TOKENIZATION §1.3
lot_im_sats        = 3_000_000_000   # 30 TSC = K/N for K=3000 TSC, N=100
lot_count          = 100
reference_premium  = 50_000_000_000  # 500 TSC, display only
series_salt = sha256(b'OPTION_SERIES_FREEZE example v1')

# --- §2 descriptor (103 bytes, fixed layout, LE) ---
descriptor = (
    bytes([descriptor_version, issuance_mode, leaf_set]) +
    writer_key +
    le32(strike_nbits) + le32(fixing_height) + le32(settle_lock_height) + le32(lambda_q) +
    le64(lot_im_sats) + le32(lot_count) + le64(reference_premium) +
    series_salt
)
assert len(descriptor) == 103, len(descriptor)

# --- §3 asset_id / series_id ---
asset_id = tagged('TSC-OptionSeries/v1', descriptor)

# --- §4.1 lot salts ---
def salt_i(i): return tagged('TSC-OptionSeries/lot', asset_id + le32(i))

# --- §4.2 sink key (counter-loop) ---
def sink(i):
    ctr = 0
    while True:
        x = tagged('TSC-OptionSeries/sink', asset_id + le32(i) + le32(ctr))
        if x_only_valid(int.from_bytes(x, 'big')):
            return ctr, x
        ctr += 1

print('descriptor_version=1  issuance_mode=0  leaf_set=1  (D1-b, self-issuance)')
print('series_salt      =', series_salt.hex())
print('descriptor (103B)=', descriptor.hex())
print('asset_id         =', asset_id.hex())
for i in (0, 1, 99):
    print(f'salt_{i:<2}          =', salt_i(i).hex())
for i in (0, 1, 99):
    ctr, sk = sink(i)
    spk = bytes([0x51, 0x20]) + sk   # OP_1 <32-byte push> = P2TR scriptPubKey
    print(f'sink_{i:<2} ctr={ctr:<2}    = key {sk.hex()}')
    print(f'sink_{i:<2} spk        =', spk.hex())
