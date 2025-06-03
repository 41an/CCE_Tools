# SM2椭圆曲线参数 (素数域256位) - GB/T 32918.5-2017
P = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF
A = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC
B = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93
N = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123


def is_valid_sm2_private_key(private_key_bytes):
    """
    验证SM2私钥合法性并返回详细错误原因
    :param private_key_bytes: 字节序列形式的私钥(32字节)
    :return: tuple (bool, str) - (是否合法, 错误描述)
    """
    # 检查长度
    if len(private_key_bytes) != 32:
        return False, f"私钥长度必须为32字节，实际为{len(private_key_bytes)}字节"

    # 转换为整数
    try:
        d = int.from_bytes(private_key_bytes, 'big')
    except Exception as e:
        return False, f"私钥转换为整数失败: {str(e)}"

    # 验证范围
    if d == 0:
        return False, "私钥不能为0"
    if d == 1:
        return False, "私钥不能为1"
    if d >= N:
        return False, f"私钥必须小于曲线阶数N(0x{N:X}...)"
    if d < 0:
        return False, "私钥不能为负数"

    # 检查常见危险值
    if d == N - 1:
        return False, "私钥不能为N-1"

    return True, "私钥合法"


def is_valid_sm2_public_key(public_key_bytes):
    """
    验证SM2公钥合法性并返回详细错误原因
    :param public_key_bytes: 字节序列形式的公钥(65字节04开头)
    :return: tuple (bool, str) - (是否合法, 错误描述)
    """
    # 检查长度
    if len(public_key_bytes) != 65:
        return False, f"公钥长度必须为65字节，实际为{len(public_key_bytes)}字节"

    # 检查前缀
    if public_key_bytes[0] != 0x04:
        return False, f"公钥必须以0x04开头(未压缩格式)，实际为0x{public_key_bytes[0]:02X}"

    # 拆分坐标
    x_bytes = public_key_bytes[1:33]
    y_bytes = public_key_bytes[33:]

    # 转换为整数
    try:
        x = int.from_bytes(x_bytes, 'big')
    except Exception as e:
        return False, f"X坐标转换失败: {str(e)}"

    try:
        y = int.from_bytes(y_bytes, 'big')
    except Exception as e:
        return False, f"Y坐标转换失败: {str(e)}"

    # 验证坐标在域内
    if not (0 <= x < P):
        return False, f"X坐标超出范围[0, P-1] (P=0x{P:X}...)"
    if not (0 <= y < P):
        return False, f"Y坐标超出范围[0, P-1] (P=0x{P:X}...)"

    # 验证曲线方程 y² ≡ x³ + ax + b (mod P)
    left = (y * y) % P
    right = (x * x * x + A * x + B) % P

    if left != right:
        # 计算详细差异用于诊断
        diff = abs(left - right) % P
        return False, f"不满足曲线方程: y² = {left:X} ≠ x³+ax+b = {right:X} (差值: 0x{diff:X})"

    # 验证是否为无穷远点（虽然私钥不会生成，但需防御性检查）
    if x == 0 and y == 0:
        return False, "公钥不能是无穷远点"

    # 验证点是否在曲线上（通过倍乘检查）
    # 注意：实际应用中可能需要更严格的检查，但会显著增加计算量
    # 这里仅验证曲线方程已足够

    return True, "公钥合法"


# 测试函数
def test_sm2_key_validation():
    """测试各种有效和无效的SM2密钥"""
    print("=" * 50)
    print("SM2密钥合法性测试")
    print("=" * 50)

    # 有效私钥示例
    valid_private = bytes.fromhex("3945208F7B2144B13F36E38AC6D39F95889393692860B51A42FB81EF4DF7C5B8")
    valid, reason = is_valid_sm2_private_key(valid_private)
    print(f"有效私钥测试: {'通过' if valid else '失败'} - {reason}")

    # 无效私钥测试
    tests = [
        (bytes(31), "过短私钥"),
        (bytes(33), "过长私钥"),
        (bytes(32), "全零私钥"),
        (int(1).to_bytes(32, 'big'), "值为1的私钥"),
        (int(N).to_bytes(32, 'big'), "等于N的私钥"),
        (int(N - 1).to_bytes(32, 'big'), "等于N-1的私钥")
    ]

    for key, desc in tests:
        valid, reason = is_valid_sm2_private_key(key)
        print(f"\n{desc}测试:")
        print(f"  预期: 无效")
        print(f"  结果: {'有效' if valid else '无效'}")
        print(f"  原因: {reason}")

    # 有效公钥示例
    valid_public = bytes.fromhex("04" +
                                 "09F9DF311E5421A150DD7D161E4BC5C672179FAD1833FC076BB08FF356F35020" +
                                 "CCEA490CE26775A52DC6EA718CC1AA600AED05FBF35E084A6632F6072DA9AD13")
    valid, reason = is_valid_sm2_public_key(valid_public)
    print(f"\n有效公钥测试: {'通过' if valid else '失败'} - {reason}")

    # 无效公钥测试
    tests = [
        (bytes(64), "过短公钥"),
        (bytes(66), "过长公钥"),
        (b"\x03" + bytes(64), "错误前缀(0x03)"),
        (b"\x04" + bytes(64), "全零坐标"),
        (valid_public[:33] + bytes(32), "修改Y坐标"),
        (b"\x04" + b"\xFF" * 64, "超大坐标值")
    ]

    for key, desc in tests:
        valid, reason = is_valid_sm2_public_key(key)
        print(f"\n{desc}测试:")
        print(f"  预期: 无效")
        print(f"  结果: {'有效' if valid else '无效'}")
        print(f"  原因: {reason}")


# 运行测试
if __name__ == "__main__":
    test_sm2_key_validation()