import os
import shutil
import subprocess
import re
import tempfile
import time

from datetime import datetime

from cryptography.hazmat.backends import default_backend

def get_public_key(path: str) -> str:
    from asn1crypto import pem, x509, keys
    try:
        with open(path, "rb") as f:
            data = f.read()

        if pem.detect(data):
            _, _, data = pem.unarmor(data)

        cert = x509.Certificate.load(data)
        spki = cert["tbs_certificate"]["subject_public_key_info"]
        algorithm = spki["algorithm"]["algorithm"].native

        if algorithm == "ec":
            # 返回04开头的未压缩公钥
            return  spki["public_key"].native.hex()
        elif algorithm == "rsa":
            # 获取 modulus 和 exponent
            rsa_pub = spki["public_key"].parsed
            rsa_public_key = keys.RSAPublicKey({
                "modulus": rsa_pub["modulus"],
                "public_exponent": rsa_pub["public_exponent"]
            })

            # 转成 DER 编码（ASN.1 标准格式）
            der_bytes = rsa_public_key.dump()
            return der_bytes.hex()
        else:
            return f"[Error] 不支持的算法: {algorithm}"

    except Exception as e:
        return f"[Error] 提取公钥失败: {e}"

def get_TBS(path: str) -> str:
    """
    从 DER 编码的证书中提取 TBS 字节，并返回十六进制字符串。
    如果发生错误，返回 None。
    """
    try:
        from asn1crypto import x509
        with open(path, 'rb') as f:
            der = f.read()

        cert = x509.Certificate.load(der)
        tbs_der = cert['tbs_certificate'].dump()
        return tbs_der.hex()
    except FileNotFoundError:
        return f"[Error] 文件未找到: {path}"
    except Exception as e:
        return f"[Error] 提取 TBS 失败: {e}"

def parse_cer_info(cer_path: str) -> dict:
    def run_openssl(inform: str) -> str:
        result = subprocess.run(
            ["openssl", "x509", "-in", cer_path, "-inform", inform, "-noout", "-text"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # window系统不弹出黑窗
            # creationflags=subprocess.CREATE_NO_WINDOW,
        )
        if result.returncode != 0:
            raise RuntimeError(f"{inform.upper()} 格式解析失败: {result.stderr.decode()}")
        return result.stdout.decode()

    output = None
    try:
        try:
            output = run_openssl("pem")
        except Exception as pem_err:
            # 回退到 DER 格式
            output = run_openssl("der")
    except Exception as e:
        return {"success": False, "error": f"OpenSSL 解析失败: {str(e)}"}

    info = {}

    sig_alg = re.search(r"Signature Algorithm: (.+)", output)
    if sig_alg:
        info["signature_algorithm"] = sig_alg.group(1).strip()

    issuer = re.search(r"Issuer: (.+)", output)
    if issuer:
        info["issuer"] = issuer.group(1).strip()

    not_before_match = re.search(r"Not Before:\s+(.+)", output)
    not_after_match = re.search(r"Not After\s*:\s+(.+)", output)

    time_format = "%b %d %H:%M:%S %Y GMT"  # OpenSSL 输出的时间格式，例如：Feb 26 08:20:50 2025 GMT
    display_format = "%Y年%m月%d日"

    if not_before_match:
        raw_not_before = not_before_match.group(1).strip()
        try:
            dt = datetime.strptime(raw_not_before, time_format)
            info["not_before"] = dt.strftime(display_format)
        except ValueError:
            info["not_before"] = raw_not_before  # fallback

    if not_after_match:
        raw_not_after = not_after_match.group(1).strip()
        try:
            dt = datetime.strptime(raw_not_after, time_format)
            info["not_after"] = dt.strftime(display_format)
        except ValueError:
            info["not_after"] = raw_not_after  # fallback

    pubkey_alg = re.search(r"Public Key Algorithm: (.+)", output)
    if pubkey_alg:
        info["public_key_algorithm"] = pubkey_alg.group(1).strip()

    pubkey_match = re.search(r"pub:\n((?:\s+[0-9a-f:]+\n)+)", output, re.IGNORECASE)
    if pubkey_match:
        hex_lines = pubkey_match.group(1).strip().split("\n")
        hex_str = ''.join(line.strip().replace(':', '') for line in hex_lines)
        info["public_key_hex"] = hex_str

    sig_match = re.search(r"Signature Value:\n((?:\s+[0-9a-f:]+\n)+)", output, re.IGNORECASE)
    if sig_match:
        sig_lines = sig_match.group(1).strip().split("\n")
        sig_hex = ''.join(line.strip().replace(':', '') for line in sig_lines)
        info["signature_value"] = sig_hex

    info["success"] = True
    info["error"] = ""

    return info

def parse_cer_safely(original_path, parse_function):
    # 检查文件是否存在
    if not os.path.isfile(original_path):
        return {"success": False, "error": f"文件不存在: {original_path}"}

    # 生成临时路径（使用时间戳 + 原扩展名）
    ext = os.path.splitext(original_path)[1]
    temp_dir = tempfile.gettempdir()  # eg. C:\Users\xxx\AppData\Local\Temp
    temp_path = os.path.join(temp_dir, f"{int(time.time())}{ext}")

    try:
        # 拷贝原始文件为临时副本
        shutil.copy2(original_path, temp_path)

        # 传递给解析函数
        result = parse_function(temp_path)

        return result

    finally:
        # 无论成功与否都清理临时文件
        if os.path.exists(temp_path):
            try:
                os.remove(temp_path)
            except Exception as e:
                print(f"[警告] 无法删除临时文件: {e}")

from cryptography import x509
def get_signature(cert_path: str) -> str:
    with open(cert_path, "rb") as f:
        der_data = f.read()

    cert = x509.load_der_x509_certificate(der_data, default_backend())
    # 获取 DER 编码的签名值
    signature_bytes = cert.signature
    # 返回十六进制字符串
    return signature_bytes.hex()


def pem_to_cer(pem_path: str) -> str:
    """
    将PEM格式证书转换为CER格式（DER编码），保存到同目录下，命名为 ECC_Tools_{原名}.cer

    :param pem_path: str，PEM格式证书的路径
    :return: str，生成的CER文件路径
    """
    if not os.path.isfile(pem_path):
        raise FileNotFoundError(f"文件不存在: {pem_path}")

    # 提取目录、文件名（不含扩展名）
    dir_name = os.path.dirname(pem_path)
    base_name = os.path.splitext(os.path.basename(pem_path))[0]
    cer_name = f"ECC_Tools_{base_name}.cer"
    cer_path = os.path.join(dir_name, cer_name)

    # 调用 openssl 转换 PEM -> DER
    try:
        subprocess.run([
            "openssl", "x509",
            "-in", pem_path,
            "-outform", "DER",
            "-out", cer_path
        ], check=True)
        print(f"[+] 生成成功: {cer_path}")
        return cer_path
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"OpenSSL 执行失败：{e}")