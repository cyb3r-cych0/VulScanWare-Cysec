import urllib.parse
import html

def mutate(payload: str):
    return {
        payload,
        urllib.parse.quote(payload),
        payload.replace("<", "%3C").replace(">", "%3E"),
    }