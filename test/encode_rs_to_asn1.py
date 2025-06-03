import gmalg
from asn1crypto.algos import DSASignature

from gmssl import sm3, func
from gmssl.sm2 import default_ecc_table
from gmssl.sm2 import CryptSM2

from func.sm2_tools import calc_sm2_digest_e



privkey_hex="23772cc112b6c533d1f5c4ab52265e9cadad6ed64dba8aa5405128f976c462e9"
pubkey_hex="040baf5ef76d6de55d59f5195389a7c5770324642f4d800b80b9ed2dd140e4f937f1dedc06fdb620a1fd8d38ac82ef22cb46e9a2efddea608867ed60439632347b"
user_id=b"1234567812345678"

sm2 = gmalg.SM2(
    bytes.fromhex(privkey_hex),
    user_id,
    bytes.fromhex(pubkey_hex),
)

msg = b"123"

# 签名
# r s 值
r, s = sm2.sign(msg)
print(r.hex())
print(s.hex())
# ASN.1
asn1_signature = encode_rs_to_asn1(r.hex(), s.hex())
print(asn1_signature.hex())

#验签
print(sm2.verify(msg, r, s))



print(calc_sm2_digest_e("31323334353637383132333435363738",b"123","040baf5ef76d6de55d59f5195389a7c5770324642f4d800b80b9ed2dd140e4f937f1dedc06fdb620a1fd8d38ac82ef22cb46e9a2efddea608867ed60439632347b"))
