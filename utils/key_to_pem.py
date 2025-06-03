from gmssl import sm2, func

from utils.gen_key import generate_sm2_keypair


def sm2_hex_private_key_to_pem(private_key_hex):
    """
    将 SM2 十六进制私钥转换为 PEM 格式
    :param private_key_hex: 64字符的十六进制私钥字符串
    :return: PEM 格式的私钥字符串
    """
    # 确保输入是64字符的十六进制字符串
    if len(private_key_hex) != 64:
        raise ValueError("Invalid SM2 private key length. Must be 64 hex characters.")

    # 添加默认公钥前缀（SM2公钥通常以'04'开头）
    public_key_hex = '04' + '00' * 64  # 临时公钥，实际不会使用

    # 创建 SM2 对象
    sm2_instance = sm2.CryptSM2(
        private_key=private_key_hex,
        public_key=public_key_hex,
        mode=sm2.default_mode,
        asn1=True
    )

    # 生成 PEM 格式的私钥
    pem_private_key = sm2_instance.export_private_key_info_pem()
    return pem_private_key.decode('utf-8')


def sm2_hex_public_key_to_pem(public_key_hex):
    """
    将 SM2 十六进制公钥转换为 PEM 格式
    :param public_key_hex: 130字符的十六进制公钥字符串（以'04'开头）
    :return: PEM 格式的公钥字符串
    """
    # 确保输入是130字符的十六进制字符串
    if len(public_key_hex) != 130:
        raise ValueError("Invalid SM2 public key length. Must be 130 hex characters.")
    if not public_key_hex.startswith('04'):
        raise ValueError("SM2 public key must start with '04'")

    # 创建 SM2 对象（私钥设为None）
    sm2_instance = sm2.CryptSM2(
        private_key=None,
        public_key=public_key_hex,
        mode=sm2.default_mode,
        asn1=True
    )

    # 生成 PEM 格式的公钥
    pem_public_key = sm2_instance.export_public_key_info_pem()
    return pem_public_key.decode('utf-8')


# 示例用法
if __name__ == "__main__":
    priv, pub = generate_sm2_keypair()
    print("私钥:", priv)
    print("公钥:", pub)

    #sm2_public_key_to_pem(pub)
    #sm2_private_key_to_pem(priv)
    # 示例密钥（实际使用时替换为真实密钥）
    private_key_hex = "289c2857d459c37f17c0d5bf1fb5a785d5d10b41d2b7e6b8b2c5b3b0f0e3d3e1f"
    public_key_hex = "04" + "32c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7" + "bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0"

    # 转换私钥
    #pem_private = sm2_hex_private_key_to_pem(priv)
    pem_private = sm2_hex_private_key_to_pem(private_key_hex)
    print("SM2 Private Key (PEM):")
    print(pem_private)

    # 转换公钥
    #pem_public = sm2_hex_public_key_to_pem(pub)
    pem_public = sm2_hex_public_key_to_pem(public_key_hex)
    print("\nSM2 Public Key (PEM):")
    print(pem_public)


