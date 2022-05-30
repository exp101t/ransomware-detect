import random
import string

_alphabet = string.ascii_lowercase + string.digits + "_"


def gen_rand_str(length: int = 16, alphabet: str = _alphabet) -> str:
    return "".join(random.choice(alphabet) for _ in range(length))
