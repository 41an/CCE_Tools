import re


def is_possible_sm3_digest(s: str) -> bool:
    return bool(re.fullmatch(r'[0-9a-fA-F]{64}', s.strip()))