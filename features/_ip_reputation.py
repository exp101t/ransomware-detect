import ipaddress
import socket

import requests

_api_url = 'https://api.abuseipdb.com/api/v2/check'

_headers = {
    'Key': open('_secrets/abuseipdb_token.txt').read()
}

_ip_num_threshold = 50


def get_ip_reputation(ip: str | list[str]) -> int:
    if isinstance(ip, list):
        if ip == []:
            return 0

        if len(ip) > _ip_num_threshold:
            return 100

        return max(get_ip_reputation(item) for item in ip)

    try:
        ip = socket.gethostbyname(ip)
    except socket.gaierror:
        return 0

    if ipaddress.ip_address(ip).is_private:
        return 0

    response = requests.get(
        _api_url,
        headers=_headers,
        params={'ipAddress': ip}).json()

    return response['data']['abuseConfidenceScore']
