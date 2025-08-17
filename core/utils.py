import base64
from datetime import datetime


def is_within_validity(start_date_str, end_date_str):
    """
    判断当前时间是否在给定的日期范围内。
    输入格式必须是：'YYYY年MM月DD日'，如 '2024年12月24日'
    """
    # 当前日期
    today = datetime.today()

    # 解析日期字符串为 datetime 对象
    try:
        start_date = datetime.strptime(start_date_str, "%Y年%m月%d日")
        end_date = datetime.strptime(end_date_str, "%Y年%m月%d日")
    except ValueError as e:
        print(f"日期格式错误: {e}")
        return False

    return start_date <= today <= end_date

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

def hex2utf8(msg: str):
    msg = msg.replace(" ", "")

    try:
        binary_data = bytes.fromhex(msg)         # Hex ➡ bytes
        return binary_data.decode("utf-8")           # bytes ➡ UTF-8 字符串
    except Exception as e:
        return f"解码失败: {e}"

def hex2base64(msg: str):
    msg = msg.replace(" ", "")

    try:
        binary_data = bytes.fromhex(msg)         # Hex ➡ bytes
        return base64.b64encode(binary_data).decode("utf-8")  # bytes ➡ base64字符串
    except Exception as e:
        return f"转换失败: {e}"

def utf82hex(msg: str):
    msg = msg.replace(" ", "")

    try:
        return msg.encode("utf-8").hex()
    except Exception as e:
        return f"转换失败: {e}"


def utf82base64(msg: str):
    msg = msg.replace(" ", "")
    try:
        return base64.b64encode(msg.encode("utf-8")).decode("utf-8")
    except Exception as e:
        return f"转换失败: {e}"


def base642hex(msg: str):
    msg = msg.replace(" ", "")

    try:
        binary = base64.b64decode(msg.encode("utf-8"), validate=True)
        return binary.hex()
    except Exception as e:
        return f"转换失败: {e}"



def base642utf8(msg: str):
    msg = msg.replace(" ", "")

    try:
        binary = base64.b64decode(msg.encode("utf-8"), validate=True)
        return binary.decode("utf-8")
    except Exception as e:
        return f"转换失败: {e}"


def days_until(target_date_str: str) -> int:
    try:
        # 解析中文格式日期
        target_date = datetime.strptime(target_date_str, "%Y年%m月%d日").date()
        today = datetime.today().date()
        delta = (target_date - today).days
        return delta
    except ValueError as e:
        print(f"[Error] 日期格式错误: {e}")
        return -1


