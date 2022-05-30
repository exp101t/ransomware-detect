import yara

_rules = yara.compile("features/crypto_signatures.yar")


def get_crypto_usage_num(data: bytes) -> int:
    return len(_rules.match(data=data))
