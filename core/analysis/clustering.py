from collections import defaultdict


def cluster_vulnerabilities(vulns):
    clusters = defaultdict(list)

    for v in vulns:
        key = f"{v.vuln_type}:{v.parameter}"
        clusters[key].append(v)
    return clusters