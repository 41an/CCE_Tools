import re
import secrets

from asn1crypto.algos import DSASignature
from gmssl import sm2, func, sm3
from gmssl.sm2 import default_ecc_table
from secrets import token_hex

# SM2椭圆曲线参数 (素数域256位) - GB/T 32918.5-2017
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


def is_valid_sm2_private_key(private_key_hex):
    """
    验证SM2私钥合法性并返回详细错误原因
    :param private_key_hex: 十六进制字符串形式的私钥(64个字符，32字节)
    :return: tuple (bool, str) - (是否合法, 错误描述)
    """
    # 清理输入（移除空格、换行和0x前缀）
    clean_hex = private_key_hex.strip().lower().replace(" ", "").replace("\n", "").replace("\r", "")
    if clean_hex.startswith("0x"):
        clean_hex = clean_hex[2:]

    # 检查长度
    if len(clean_hex) != 64:
        return False, f"私钥长度必须为64个十六进制字符(32字节)，实际为{len(clean_hex)}字符"

    # 转换为字节
    try:
        private_key_bytes = bytes.fromhex(clean_hex)
    except ValueError:
        return False, "私钥包含无效的十六进制字符"

    # 转换为整数
    try:
        d = int(clean_hex, 16)
    except Exception as e:
        return False, f"私钥转换为整数失败: {str(e)}"

    # 验证范围
    if d == 0:
        return False, "私钥不能为0"
    if d == 1:
        return False, "私钥不能为1"
    if d >= N:
        return False, f"私钥必须小于曲线阶数N(0x{N:X})"
    if d < 0:
        return False, "私钥不能为负数"

    # 检查常见危险值
    if d == N - 1:
        return False, "私钥不能为N-1"

    return True, "私钥合法"

def is_valid_sm2_public_key(public_key_hex):
    """
    验证SM2公钥合法性并返回详细错误原因
    :param public_key_hex: 十六进制字符串形式的公钥(130个字符，65字节，以'04'开头)
    :return: tuple (bool, str) - (是否合法, 错误描述)
    """
    # 清理输入（移除空格、换行和0x前缀）
    clean_hex = public_key_hex.strip().lower().replace(" ", "").replace("\n", "").replace("\r", "")
    if clean_hex.startswith("0x"):
        clean_hex = clean_hex[2:]

    # 检查长度
    if len(clean_hex) != 130:
        return False, f"公钥长度必须为130个十六进制字符(65字节)，实际为{len(clean_hex)}字符"

    # 检查前缀
    if not clean_hex.startswith("04"):
        return False, f"公钥必须以'04'开头(未压缩格式)，实际为'{clean_hex[:2]}'"

    # 拆分坐标
    x_hex = clean_hex[2:66]  # 64字符 = 32字节
    y_hex = clean_hex[66:130]  # 64字符 = 32字节

    # 转换为整数
    try:
        x = int(x_hex, 16)
    except Exception as e:
        return False, f"X坐标转换失败: {str(e)}"

    try:
        y = int(y_hex, 16)
    except Exception as e:
        return False, f"Y坐标转换失败: {str(e)}"

    # 验证坐标在域内
    if not (0 <= x < P):
        return False, f"X坐标超出范围[0, P-1] (P=0x{P:X})"
    if not (0 <= y < P):
        return False, f"Y坐标超出范围[0, P-1] (P=0x{P:X})"

    # 验证曲线方程 y² ≡ x³ + ax + b (mod P)
    left = (y * y) % P
    right = (x * x * x + A * x + B) % P

    if left != right:
        # 计算详细差异用于诊断
        diff = (left - right) % P
        return False, f"不满足曲线方程: y² = {left & 0xFFFFF}... ≠ x³+ax+b = {right & 0xFFFFF}... (差值: 0x{diff & 0xFFFFF}...)"

    # 验证是否为无穷远点
    if x == 0 and y == 0:
        return False, "公钥不能是无穷远点"

    return True, "公钥合法"

def is_valid_sm2_uid(uid):
    """
    判断SM2 UID（用户标识）是否合法

    参数:
        uid: 可以是字符串或字节串(bytes)

    返回:
        tuple: (is_valid: bool, message: str)
            is_valid: True表示合法，False表示不合法
            message: 详细的验证结果消息
    """
    # 检查输入类型并转换为字节串
    if isinstance(uid, str):
        try:
            uid_bytes = uid.encode('utf-8')
        except UnicodeEncodeError:
            return False, "错误：无法将字符串编码为UTF-8字节"
    elif isinstance(uid, bytes):
        uid_bytes = uid
    else:
        return False, "错误：UID必须是字符串或字节串类型"

    # 1. 长度检查（标准建议16字节，但不是强制要求）
    uid_length = len(uid_bytes)
    if uid_length == 0:
        return False, "错误：UID不能为空"

    # 2. 内容检查（允许任意二进制数据，但推荐可打印字符）
    # 这里不强制内容，但检查是否有控制字符（可选）
    if any(byte < 32 or byte > 126 for byte in uid_bytes):
        return True, f"警告：UID包含非打印字符（长度: {uid_length}字节）"

    # 3. 默认UID检查（标准默认UID："1234567812345678"）
    if uid_bytes == b"1234567812345678":
        return True, "警告：使用默认UID（1234567812345678），建议使用自定义UID"

    # 4. 长度建议（标准建议16字节）
    if uid_length != 16:
        return True, f"注意：UID长度({uid_length}字节)非标准16字节，但可以使用"

    return True, "UID验证通过"

# 判断签名值是否合法，合法则转换为标准格式
def convert_signature(signature_hex):
    """
    转换SM2签名格式：
    - 如果是ASN.1 DER格式，直接返回
    - 如果是RS拼接格式（64字节），转换为ASN.1 DER格式
    - 其他情况返回错误

    参数:
        signature_hex (str): 十六进制字符串格式的签名

    返回:
        str: 转换后的十六进制字符串或错误消息
    """
    # 清理输入（移除空格、冒号等非十六进制字符）
    clean_hex = re.sub(r'[^0-9a-fA-F]', '', signature_hex)

    # 检查是否为有效十六进制
    if not clean_hex or len(clean_hex) % 2 != 0:
        return "错误：无效的十六进制字符串"

    # 尝试解析为ASN.1 DER格式
    if is_valid_asn1(clean_hex):
        return clean_hex.lower()  # 返回标准化的十六进制

    # 尝试解析为RS格式（固定64字节）
    if len(clean_hex) == 128:  # 64字节 = 128字符
        return rs_to_asn1(clean_hex)

    # 尝试解析为RS格式（变长）
    if len(clean_hex) % 2 == 0 and len(clean_hex) >= 128:
        return rs_to_asn1(clean_hex)

    return "错误：无法识别的签名格式"


def is_valid_asn1(hex_str):
    """检查是否为有效的ASN.1 DER格式签名"""
    try:
        # 基本结构检查
        if not hex_str.startswith('30'):
            return False

        # 解析长度字段
        length_byte = int(hex_str[2:4], 16)
        pos = 4

        # 处理长格式长度
        if length_byte & 0x80:
            num_bytes = length_byte & 0x7F
            if num_bytes == 0 or num_bytes > 2:
                return False  # 不支持过长的长度字段

            total_length = int(hex_str[pos:pos + num_bytes * 2], 16)
            pos += num_bytes * 2
        else:
            total_length = length_byte

        # 检查总长度匹配
        remaining = len(hex_str) // 2 - (pos // 2)
        if total_length != remaining:
            return False

        # 检查R整数结构
        if hex_str[pos:pos + 2] != '02':
            return False
        r_len = int(hex_str[pos + 2:pos + 4], 16)
        pos += 4 + r_len * 2

        # 检查S整数结构
        if hex_str[pos:pos + 2] != '02':
            return False
        s_len = int(hex_str[pos + 2:pos + 4], 16)
        pos += 4 + s_len * 2

        # 检查是否完整解析
        return pos == len(hex_str)
    except:
        return False


def rs_to_asn1(hex_str):
    """将RS格式转换为ASN.1 DER格式"""
    # 尝试固定长度分割（64字节）
    if len(hex_str) == 128:
        r_hex = hex_str[:64]
        s_hex = hex_str[64:]
    else:
        # 变长处理：尝试找到中间点
        mid = len(hex_str) // 2
        if mid % 2 != 0:
            mid += 1  # 确保字节对齐
        r_hex = hex_str[:mid]
        s_hex = hex_str[mid:]

    # 转换为整数
    try:
        r_int = int(r_hex, 16)
        s_int = int(s_hex, 16)
    except ValueError:
        return "错误：无效的RS格式整数"

    # 转换为DER字节
    r_bytes = int_to_der_bytes(r_int)
    s_bytes = int_to_der_bytes(s_int)

    # 构建ASN.1结构
    total_bytes = r_bytes + s_bytes
    der_bytes = b'\x30' + encode_length(len(total_bytes)) + total_bytes

    return der_bytes.hex().lower()


def int_to_der_bytes(value):
    """将整数转换为DER格式的字节串"""
    # 转换为大端字节
    value_bytes = value.to_bytes((value.bit_length() + 7) // 8 or 1, 'big')

    # 处理最高位为1的情况（DER要求正数表示）
    if value_bytes[0] & 0x80:
        value_bytes = b'\x00' + value_bytes

    # 添加DER整数标签和长度
    return b'\x02' + encode_length(len(value_bytes)) + value_bytes


def encode_length(length):
    """编码DER长度字段"""
    if length < 128:
        return bytes([length])
    elif length < 256:
        return b'\x81' + bytes([length])
    else:
        return b'\x82' + length.to_bytes(2, 'big')


#  封装为 ASN.1 格式
def encode_rs_to_asn1(r_hex, s_hex):
    r_int = int(r_hex, 16)
    s_int = int(s_hex, 16)
    ds = DSASignature({'r': r_int, 's': s_int})
    return ds.dump()

def extract_rs_from_asn1(signature_hex: str) -> tuple[str, str]:
    """
    从 ASN.1 DER 编码的 SM2 签名中提取 R 和 S
    参数:
        signature_hex: ASN.1 编码的签名（十六进制字符串）
    返回:
        (R, S): 十六进制字符串形式的 R 和 S（去除前导 0）
    """
    import binascii

    data = bytearray.fromhex(signature_hex)

    if data[0] != 0x30:
        raise ValueError("不是合法的ASN.1 SEQUENCE结构")

    idx = 2  # 跳过 0x30 和总长度
    if data[idx] != 0x02:
        raise ValueError("R字段缺失")

    r_len = data[idx + 1]
    r = data[idx + 2:idx + 2 + r_len]
    idx = idx + 2 + r_len

    if data[idx] != 0x02:
        raise ValueError("S字段缺失")

    s_len = data[idx + 1]
    s = data[idx + 2:idx + 2 + s_len]

    # 去掉前导 0（用于避免负数）
    r = r.lstrip(b'\x00')
    s = s.lstrip(b'\x00')

    return r.hex(), s.hex()

# 生成密钥对
def generate_sm2_keypair():
    # 生成 SM2 私钥（256位 = 64 hex字符）
    private_key = func.random_hex(64)

    # 先创建一个临时 sm2 对象，用于生成公钥（kg 函数）
    tmp_sm2 = sm2.CryptSM2(private_key=private_key, public_key='')
    public_key = tmp_sm2._kg(int(private_key, 16), tmp_sm2.ecc_table['g'])

    # 现在传入完整的密钥对
    sm2_crypt = sm2.CryptSM2(private_key=private_key, public_key=public_key)

    # print("SM2 Private Key (hex):", private_key)
    # print("SM2 Public Key (hex, uncompressed):", "04" + public_key)
    return private_key,'04'+public_key

# 计算e值
def calc_sm2_digest_e(id_hex: str, msg: bytes, pub_key_hex: str) -> str:
    """
    根据 SM2 签名标准计算 Z || M 的 SM3 摘要 e

    :param id_hex:       用户ID的十六进制字符串，例如 "31323334353637383132333435363738"（代表"1234567812345678"）
    :param msg:          原始消息，字节串，例如 b"123"
    :param pub_key_hex:  SM2公钥（未压缩04开头），长度为130字符（04 + 64字节）
    :return:             e = SM3(Z || M)，十六进制字符串
    """
    # 1. 参数 a, b, Gx, Gy, p
    a = int(default_ecc_table['a'], 16)
    b = int(default_ecc_table['b'], 16)
    gx = int(default_ecc_table['g'][0:64], 16)
    gy = int(default_ecc_table['g'][64:], 16)
    p = int(default_ecc_table['p'], 16)

    # 2. 公钥拆分
    px = int(pub_key_hex[2:66], 16)
    py = int(pub_key_hex[66:], 16)

    # 3. 用户ID处理
    entl = len(bytes.fromhex(id_hex)) * 8
    entl_bytes = entl.to_bytes(2, byteorder='big')

    z_input = (
        entl_bytes +
        bytes.fromhex(id_hex) +
        a.to_bytes(32, 'big') +
        b.to_bytes(32, 'big') +
        gx.to_bytes(32, 'big') +
        gy.to_bytes(32, 'big') +
        px.to_bytes(32, 'big') +
        py.to_bytes(32, 'big')
    )

    z = sm3.sm3_hash(func.bytes_to_list(z_input))  # 计算 Z = SM3(ENTL || ID || a || b || Gx || Gy || Px || Py)

    zm = bytes.fromhex(z) + msg
    e = sm3.sm3_hash(func.bytes_to_list(zm))       # 计算 e = SM3(Z || M)
    return e


from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from gmssl import sm2

def sm2_hex_priv_to_pem(priv_hex: str) -> str:
    private_int = int(priv_hex, 16)
    fake_key = ec.derive_private_key(private_int, ec.SECP256R1())  # 伪装成 P-256
    pem = fake_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    return pem.decode()

# 生成pem格式密钥对
def generate_sm2_key_pair():
    """
    使用 cryptography 库生成 SM2 密钥对
    返回: (private_key_pem, public_key_pem)
    """
    # 创建 SM2 私钥（使用 brainpoolP256r1 曲线，与 SM2 参数兼容）
    private_key = ec.generate_private_key(
        ec.BrainpoolP256R1(),
        default_backend()
    )

    # 序列化私钥
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )

    # 序列化公钥
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )

    return private_pem.decode('utf-8'), public_pem.decode('utf-8')


# def is_valid_signature(signature: str) -> bool:
#     """
#     验证签名是否合法（是否为有效的十六进制字符串）
#
#     参数:
#         signature: 待验证的签名字符串
#
#     返回:
#         bool: True 表示合法，False 表示不合法
#     """
#     # 1. 基本检查：非空
#     if not signature:
#         return False
#
#     # 2. 检查是否只包含十六进制字符（0-9, a-f, A-F）
#     hex_chars = set("0123456789abcdefABCDEF")
#     if not all(char in hex_chars for char in signature):
#         return False
#
#     # 3. 检查长度是否合理（SM2签名通常是128-144个字符）
#     length = len(signature)
#     if length < 128 or length > 144:  # 64-72字节的十六进制表示
#         return False
#
#     return True





# 示例用法
if __name__ == "__main__":
    private_pem, public_pem = generate_sm2_key_pair()
    print("私钥 (PEM):")
    print(private_pem)
    print("\n公钥 (PEM):")
    print(public_pem)

    pri,pub=generate_sm2_keypair()
    print(pri)
    print(pub)
    print("########")

    print(sm2_hex_priv_to_pem("27490a8370df503e965dcfba7f26d708fb4062a8519a611d40055fbc59518d21"))