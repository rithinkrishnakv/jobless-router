from .models import Incident

SUBTITLE = "Reincarnated in a Tier-1 Scrubbing Center to Master BGP Flowspec"


def render(incident: Incident, mitigation_text: str = "") -> str:
    ev = incident.event
    lines = []
    lines.append("# Jobless-Router Threat Intelligence Report")
    lines.append(f"*{SUBTITLE}*")
    lines.append("")
    lines.append(f"**Prefix:** `{ev.prefix}`  ")
    lines.append(f"**Origin AS:** AS{ev.origin_asn}  ")
    lines.append(f"**Observed via collector:** {ev.collector}  ")
    lines.append(f"**RPKI verdict:** `{incident.rpki.state.value}` -- {incident.rpki.note}")
    lines.append("")
    lines.append("## AS-Path Traversal")
    lines.append(f"`{' -> '.join(str(a) for a in ev.as_path)}`")
    if incident.complicit_upstream:
        lines.append(
            f"**Complicit upstream:** AS{incident.complicit_upstream} accepted this announcement "
            f"directly from the origin and propagated it onward without filtering it."
        )
    lines.append("")
    lines.append("## Path Integrity")
    lines.append(f"- **Anomaly type:** {incident.path_anomaly.kind} -- {incident.path_anomaly.detail}")
    lines.append(f"- **Valley-free:** {'yes' if incident.valley.is_valley_free else 'NO'} -- {incident.valley.detail}")
    lines.append("")
    lines.append("## BGP Communities")
    if incident.community_tags:
        for tag in incident.community_tags:
            lines.append(f"- {tag}")
    else:
        lines.append("- none attached")
    lines.append("")
    lines.append("## Intent Heuristic")
    lines.append(f"- Fat-finger score: **{incident.intent.fat_finger_score}/100**")
    lines.append(f"- Targeted-MITM score: **{incident.intent.targeted_mitm_score}/100**")
    lines.append(f"- **Verdict: {incident.intent.label}** (confidence {incident.intent.confidence}/100)")
    lines.append("")
    lines.append("## Blast Radius")
    lines.append(
        f"- Seen at {incident.blast.collectors_seen}/{incident.blast.collectors_total} known RIS vantage points "
        f"(~{incident.blast.pct_estimate}% sampled propagation)"
    )
    if incident.blast.regions:
        lines.append(f"- Regions: {', '.join(incident.blast.regions)}")
    if incident.ct_flags:
        lines.append("")
        lines.append("## Certificate Transparency Cross-Check")
        for f in incident.ct_flags:
            lines.append(f"- {f}")
    if mitigation_text:
        lines.append("")
        lines.append("## Suggested Mitigation (advisory -- review before use)")
        lines.append("```")
        lines.append(mitigation_text)
        lines.append("```")
    return "\n".join(lines)
