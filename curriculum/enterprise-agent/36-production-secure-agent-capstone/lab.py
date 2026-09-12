"""Capstone release gate based on recorded security evidence."""
REQUIRED_DOSSIER = {"architecture", "threat_model", "invariants", "attack_matrix", "controls", "telemetry", "incident_timeline", "residual_risks", "production_decision"}
REQUIRED_CONTROLS = {"authorization", "context_policy", "memory_policy", "egress_policy", "delegation_policy", "approval", "kill_switch", "release_gate"}

def assess(dossier: dict) -> dict:
    missing = sorted(REQUIRED_DOSSIER - set(dossier))
    missing_controls = sorted(REQUIRED_CONTROLS - set(dossier.get("controls", [])))
    severe = dossier.get("severe_attack_successes", 0)
    return {"ready": not missing and not missing_controls and severe == 0 and dossier.get("production_decision") == "approve", "missing": missing, "missing_controls": missing_controls, "severe_attack_successes": severe}

if __name__ == "__main__":
    dossier = {"architecture":"v1","threat_model":"v1","invariants":["tenant=0"],"attack_matrix":"v1","controls":sorted(REQUIRED_CONTROLS),"telemetry":"v1","incident_timeline":"v1","residual_risks":["model error"],"production_decision":"approve","severe_attack_successes":0}
    assert assess(dossier)["ready"]
    assert not assess({**dossier, "severe_attack_successes":1})["ready"]
    print("capstone dossier gate passed")
