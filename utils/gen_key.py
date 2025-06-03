from gmssl import sm2
import os

def generate_sm2_keypair():
    """
    生成 SM2 密钥对，返回 (private_key_hex, public_key_hex)
    - 私钥：64字节 hex 字符串
    - 公钥：130字节 hex 字符串（04 开头，未压缩格式）
    """
    private_key = os.urandom(32)
    private_key_hex = private_key.hex()

    sm2_crypt = sm2.CryptSM2(private_key=private_key_hex, public_key="")  # public_key不能为None

    # 使用私钥生成公钥（X + Y，不含04前缀）
    pub_key_raw = sm2_crypt._kg(int(private_key_hex, 16), sm2_crypt.ecc_table['g'])

    public_key_hex = '04' + pub_key_raw  # 添加04前缀，变成未压缩格式
    return private_key_hex, public_key_hex

