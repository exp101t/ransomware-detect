import pefile


def get_max_entropy(pe_bytes: bytes) -> float:
    pe_info: dict = pefile.PE(data=pe_bytes).dump_dict()

    return max(section['Entropy'] for section in pe_info['PE Sections'])
