import hashlib
import sys

import pandas as pd

from collectors.anyrun import AnyRunTask, CachedAnyRunTask
from features import (
    get_bad_imports_num,
    get_connections_num,
    get_crypto_usage_num,
    get_file_modification_rate,
    get_ip_reputation,
    get_max_entropy,
    get_started_processes_num,
    get_traffic_size_download,
    get_traffic_size_upload,
)
from time import sleep


def extract_features(task: AnyRunTask) -> dict:
    return {
        "sample_hash": hashlib.sha256(task.sample_bytes).hexdigest(),
        "bad_imports": get_bad_imports_num(task.sample_bytes),
        "connections_num": get_connections_num(task),
        "crypto_usage": get_crypto_usage_num(task.sample_bytes),
        "modification_rate": get_file_modification_rate(task),
        "ip_reputation": get_ip_reputation(task.ips),
        "max_entropy": get_max_entropy(task.sample_bytes),
        "bytes_download": get_traffic_size_download(task),
        "bytes_upload": get_traffic_size_upload(task),
        "started_processes": get_started_processes_num(task),
    }


filename = sys.argv[1]

with open("_secrets/login_token.txt", "r") as handle:
    login_token: str = handle.read()

result = []

with open(filename, "r") as handle:
    for line in handle:
        try:
            link = line.strip()

            if link == "" or link.startswith("#"):
                continue

            uuid = link[26:-1]

            with CachedAnyRunTask(uuid, login_token) as task:
                if len(task.processes) > 0:
                    print(f"Handling task {uuid}")
                    result.append(extract_features(task))
                    print(f"Handling done {uuid}")
                else:
                    print(f"Skipping {uuid}")
        except Exception as e:
            print(str(e))
            print(f"Skipping {uuid}")

        print('sleeping')
        sleep(10)

df = pd.DataFrame(result)

df.to_csv(sys.argv[2])
