from core.payloads.contexts import ALL_PAYLOADS
from core.payloads.mutator import mutate
import random
import string


def token():
    return "VSW_" + "".join(random.choices(string.ascii_uppercase + string.digits, k=6))


def get_payloads(context: str = None):
    results = []

    for p in ALL_PAYLOADS:
        if context and p.context != context:
            continue
        for m in mutate(p.value):
            t = token()

            payload = m.replace("alert(1)", f'alert("{t}")')

            results.append({
                "payload": payload,
                "context": p.context
            })

    return results
