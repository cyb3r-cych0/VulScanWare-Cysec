from core.payloads.contexts import ALL_PAYLOADS
from core.payloads.mutator import mutate

def get_payloads(context: str = None):
    results = []

    for p in ALL_PAYLOADS:
        if context and p.context != context:
            continue
        for m in mutate(p.value):
            results.append({
                "payload": m,
                "context": p.context
            })

    return results
