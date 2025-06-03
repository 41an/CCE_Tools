from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.backends import default_backend
import binascii


def hex_to_pem(hex_private_key: str, password: bytes = None) -> str:
    """使用cryptography库的HEX转PEM"""
    # 清理十六进制字符串
    clean_hex = hex_private_key.strip().lower()
    if clean_hex.startswith("0x"):
        clean_hex = clean_hex[2:]

    if len(clean_hex) != 64:
        raise ValueError("无效的私钥长度")

    # 转换为整数
    private_value = int(clean_hex, 16)

    # 创建私钥对象 (使用SM2兼容的曲线)
    private_key = ec.derive_private_key(
        private_value,
        ec.SECP256R1(),  # 与SM2使用相同的曲线参数
        default_backend()
    )

    # 序列化为PEM
    return private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(
            password) if password else serialization.NoEncryption()
    ).decode('utf-8')


def pem_to_hex(pem_private_key: str, password: bytes = None) -> str:
    """使用cryptography库的PEM转HEX"""
    # 加载私钥
    private_key = serialization.load_pem_private_key(
        pem_private_key.encode('utf-8'),
        password=password,
        backend=default_backend()
    )

    # 提取私钥值
    private_value = private_key.private_numbers().private_value

    # 转换为十六进制
    return f"{private_value:064x}"


# 测试
if __name__ == "__main__":
    test_hex = "3945208f7b2144b13f36e38ac6d39f95889393692860b51a42fb81ef4df7c5b8"

    # 转换测试
    pem = hex_to_pem(test_hex)
    print(pem)

    hex_result = pem_to_hex(pem)
    print(hex_result)

    assert test_hex.lower() == hex_result.lower()
    print("转换成功!")