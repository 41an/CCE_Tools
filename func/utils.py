import base64


# base64 <-- --> UTF-8
def convert_format(msg: str, from_format: str, to_format: str) -> str:
    from_format = from_format.lower()
    to_format = to_format.lower()
    try:
        if from_format == "utf-8" and to_format == "base64":
            # UTF-8 ➡ Base64
            return base64.b64encode(msg.encode('utf-8')).decode('utf-8')

        elif from_format == "base64" and to_format == "utf-8":
            # Base64 ➡ UTF-8
            decoded_bytes = base64.b64decode(msg.encode('utf-8'), validate=True)
            return decoded_bytes.decode('utf-8')

        elif from_format == "base64" and to_format == "base64":
            # Base64 ➡ Base64 (试图解码后再次编码)
            try:
                decoded_bytes = base64.b64decode(msg.encode('utf-8'), validate=True)
                reencoded = base64.b64encode(decoded_bytes).decode('utf-8')
                return reencoded
            except Exception:
                return msg  # 无法解码说明原始 msg 不是合法的 base64，直接返回

        elif from_format == "utf-8" and to_format == "utf-8":
            return msg

        else:
            return "未知类型"

    except Exception:
        return "转换失败"

# base64/UTF-8 --> hex
def convert_to_hex(msg: str, to_format: str = "hex") -> str:
    to_format = to_format.lower()

    try:
        if to_format != "hex":
            return "暂不支持目标格式"

        # 所有字符串统一按 UTF-8 编码转 hex
        return msg.encode("utf-8").hex()

    except Exception as e:
        return "格式转换失败: " + str(e)

# hex --> de'c
def convert_to_dec(msg: str, to_format: str = "dec") -> str:
    to_format = to_format.lower()
    msg = msg.replace(" ", "")

    try:
        # 将十六进制字符串转换为 bytes
        byte_data = bytes.fromhex(msg)
        # 将 bytes 解码为 UTF-8 字符串
        return byte_data.decode('utf-8')
    except Exception as e:
        return f"格式转换失败: {e}"

