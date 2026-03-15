import random
import string
from core.payloads.mutator import mutate
from core.payloads.contexts import ALL_PAYLOADS


def token():
    return "VSW_" + "".join(
        random.choices(string.ascii_uppercase + string.digits, k=6)
    )

def get_payloads(context: str = None):
    results = []

    for p in ALL_PAYLOADS:
        if context and p.context != context:
            continue

        mutated = mutate(p.value)
        if not mutated:
            mutated = [p.value]

        for m in mutated:
            t = token()
            payload = m.replace("alert(1)", f'alert("{t}")')
            results.append({
                "payload": payload,
                "context": p.context
            })
    return results