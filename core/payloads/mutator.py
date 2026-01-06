import urllib.parse
import html

def mutate(payload: str):
    return {
        payload,
        urllib.parse.quote(payload),
        html.escape(payload),
        payload.replace("<", "%3C").replace(">", "%3E"),
    }
