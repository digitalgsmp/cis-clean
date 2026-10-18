import re

def parse_duration(text: str) -> int:
    if not isinstance(text, str):
        raise ValueError("Input must be a string")
    m = re.fullmatch(r"([0-9]+)([smhd])", text)
    if m is None:
        raise ValueError("Invalid duration format")
    value = int(m.group(1))
    unit = m.group(2)
    multipliers = {"s": 1, "m": 60, "h": 3600, "d": 86400}
    return value * multipliers[unit]
