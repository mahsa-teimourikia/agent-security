"""Capstone release gate based on recorded security evidence."""
REQUIRED_DOSSIER = {"architecture", "threat_model", "invariants", "attack_matrix", "controls", "telemetry", "incident_timeline", "residual_risks", "production_decision"}
REQUIRED_CONTROLS = {"authorization", "context_policy", "memory_policy", "egress_policy", "delegation_policy", "approval", "kill_switch", "release_gate"}

def assess(dossier: dict) -> dict:
    missing = sorted(REQUIRED_DOSSIER - set(dossier))
    controls = dossier.get("controls") if isinstance(dossier.get("controls"), dict) else {}
    missing_controls = sorted(REQUIRED_CONTROLS - set(controls))
    invalid = []
    for key in ("architecture", "threat_model", "attack_matrix", "telemetry", "incident_timeline"):
        if not isinstance(dossier.get(key), str) or not dossier.get(key, "").strip():
            invalid.append(key)
    if not isinstance(dossier.get("invariants"), list) or not dossier.get("invariants"):
        invalid.append("invariants")
    if any(not isinstance(controls.get(name), str) or not controls.get(name, "").strip() for name in REQUIRED_CONTROLS):
        invalid.append("control-evidence")
    risks = dossier.get("residual_risks")
    if not isinstance(risks, list) or any(
        not isinstance(risk, dict) or not all(risk.get(field) for field in ("risk", "owner", "decision"))
        for risk in risks
    ):
        invalid.append("residual_risks")
    severe = dossier.get("severe_attack_successes")
    if not isinstance(severe, int) or isinstance(severe, bool) or severe < 0:
        invalid.append("severe_attack_successes")
    ready = (
        not missing
        and not missing_controls
        and not invalid
        and severe == 0
        and dossier.get("production_decision") == "approve"
    )
    return {"ready": ready, "missing": missing, "missing_controls": missing_controls, "invalid": sorted(set(invalid)), "severe_attack_successes": severe}

if __name__ == "__main__":
    dossier = {"architecture":"architecture-v1","threat_model":"threat-model-v1","invariants":["cross_tenant_access == 0"],"attack_matrix":"attack-matrix-v1","controls":{name:f"evidence:{name}:v1" for name in REQUIRED_CONTROLS},"telemetry":"trace-suite-v1","incident_timeline":"drill-2026-08-11","residual_risks":[{"risk":"model error","owner":"agent-platform","decision":"accept-with-monitoring"}],"production_decision":"approve","severe_attack_successes":0}
    assert assess(dossier)["ready"]
    assert not assess({**dossier, "severe_attack_successes":1})["ready"]
    print("capstone dossier gate passed")
