def score_vulnerability(contexts, payload):

    score = 0

    # context weighting
    if "javascript" in contexts:
        score += 70
    elif "attribute" in contexts:
        score += 50
    elif "html" in contexts:
        score += 30
    else:
        score += 10

    # payload strength
    dangerous = ["<script", "onerror", "onload", "javascript:"]
    if any(p in payload.lower() for p in dangerous):
        score += 20

    # severity mapping
    if score >= 80:
        return "critical"
    elif score >= 60:
        return "high"
    elif score >= 40:
        return "medium"
    else:
        return "low"