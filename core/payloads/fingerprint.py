import random
import string
import re


def generate_token():
    return "VSW_" + "".join(
        random.choices(string.ascii_uppercase + string.digits, k=6)
    )

def fingerprint_payload(payload: str):
    token = generate_token()
    payload = re.sub(
        r'alert\((?:1|"1"|\'1\')\)',
        f'alert("{token}")',
        payload
    )
    return payload, token