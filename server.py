#!/usr/bin/env python3
"""
HL7 / FHIR Bridge MCP — part of the CSOAI Layer-0 legacy-bridge family.

Connects healthcare legacy messaging (HL7 v2 pipe-delimited) and modern FHIR to
ONE OS / CSOAI — parse, validate, map HL7v2 -> FHIR, and GOVERN PHI (HIPAA / MDR /
EU AI Act Annex I). Sibling of cobol-bridge-mcp.

Tools: parse_hl7v2 · hl7_to_fhir · validate_fhir · govern_phi
"""
from mcp.server.fastmcp import FastMCP
from pydantic import BaseModel, Field
from typing import List, Dict, Any, Optional
import json

mcp = FastMCP("HL7/FHIR Bridge", instructions="Bridge healthcare HL7 v2 + FHIR to ONE OS — parse, map, validate, and govern PHI (HIPAA/MDR).")

# ── SIGIL: every governed action → one signed hash-chained hop (SIGIL_LOG unifies all layers) ──
import hashlib as _hl, time as _t, json as _j, os as _os
_SIGIL_LOG = _os.environ.get("SIGIL_LOG", _os.path.join(_os.path.dirname(_os.path.abspath(__file__)), "bridge_sigil.log"))
def _sigil(op, body):
    try:
        prev = ""
        if _os.path.exists(_SIGIL_LOG):
            with open(_SIGIL_LOG) as f:
                ls = f.readlines()
                if ls: prev = _j.loads(ls[-1]).get("digest", "")
        ts = int(_t.time()); dg = _hl.sha256(f"{op}|{ts}|{prev[:8]}|{body}".encode()).hexdigest()[:16]
        _os.makedirs(_os.path.dirname(_SIGIL_LOG), exist_ok=True)
        with open(_SIGIL_LOG, "a") as f: f.write(_j.dumps({"ts": ts, "op": op, "body": body, "prev_digest": prev, "digest": dg}) + "\n")
        return dg
    except Exception: return ""

HL7_MSG = {
    "ADT": "Admit/Discharge/Transfer", "ORU": "Observation Result",
    "ORM": "Order Message", "SIU": "Scheduling", "MDM": "Medical Document",
}


class HL7Parsed(BaseModel):
    message_type: str
    description: str
    patient_id: Optional[str] = None
    patient_name: Optional[str] = None
    dob: Optional[str] = None
    sending_app: Optional[str] = None
    segments: List[str] = Field(default_factory=list)
    segment_count: int = 0


class Validation(BaseModel):
    valid: bool
    resource_type: Optional[str] = None
    errors: List[str] = Field(default_factory=list)
    warnings: List[str] = Field(default_factory=list)


class PHIGovernance(BaseModel):
    phi_fields_present: List[str] = Field(default_factory=list)
    risk_flags: List[str] = Field(default_factory=list)
    frameworks: List[str] = Field(default_factory=list)
    minimisation_advice: str = ""
    attestable: bool = True


def _segments(hl7: str) -> List[List[str]]:
    out = []
    for line in hl7.replace("\r\n", "\r").replace("\n", "\r").split("\r"):
        line = line.strip()
        if line:
            out.append(line.split("|"))
    return out


@mcp.tool()
def parse_hl7v2(message: str) -> HL7Parsed:
    """Parse an HL7 v2 pipe-delimited message; extract message type + key patient fields."""
    segs = _segments(message)
    seg_names = [s[0] for s in segs if s]
    mt = "unknown"
    sending = None
    for s in segs:
        if s and s[0] == "MSH":
            sending = s[2] if len(s) > 2 else None
            if len(s) > 8 and s[8]:
                mt = s[8].split("^")[0]
    pid_name = pid_id = dob = None
    for s in segs:
        if s and s[0] == "PID":
            pid_id = s[3].split("^")[0] if len(s) > 3 and s[3] else None
            if len(s) > 5 and s[5]:
                parts = s[5].split("^")
                pid_name = " ".join(p for p in [parts[1] if len(parts) > 1 else "", parts[0]] if p).strip()
            dob = s[7] if len(s) > 7 and s[7] else None
    return HL7Parsed(
        message_type=mt,
        description=HL7_MSG.get(mt, "HL7 v2 message"),
        patient_id=pid_id, patient_name=pid_name, dob=dob,
        sending_app=sending, segments=seg_names, segment_count=len(segs),
    )


@mcp.tool()
def hl7_to_fhir(message: str) -> Dict[str, Any]:
    """Map an HL7 v2 message to a minimal FHIR R4 Patient + MessageHeader bundle for ONE OS."""
    p = parse_hl7v2(message)
    name = []
    if p.patient_name:
        parts = p.patient_name.split(" ")
        name = [{"family": parts[-1], "given": parts[:-1]}]
    patient = {"resourceType": "Patient", "id": p.patient_id or "unknown", "name": name}
    if p.dob and len(p.dob) >= 8:
        patient["birthDate"] = f"{p.dob[0:4]}-{p.dob[4:6]}-{p.dob[6:8]}"
    return {
        "resourceType": "Bundle", "type": "message",
        "entry": [
            {"resource": {"resourceType": "MessageHeader", "eventCoding": {"code": p.message_type}, "source": {"name": p.sending_app}}},
            {"resource": patient},
        ],
        "source_standard": "HL7 v2", "target_standard": "FHIR R4",
    }


@mcp.tool()
def validate_fhir(resource_json: str) -> Validation:
    """Validate a FHIR resource/bundle (well-formed JSON + required resourceType + basic shape)."""
    errors: List[str] = []
    warnings: List[str] = []
    try:
        r = json.loads(resource_json)
    except json.JSONDecodeError as e:
        return Validation(valid=False, errors=[f"Not valid JSON: {e}"])
    rt = r.get("resourceType")
    if not rt:
        errors.append("Missing required 'resourceType'")
    if rt == "Patient" and not r.get("name"):
        warnings.append("Patient has no name element")
    if rt == "Bundle" and not r.get("entry"):
        warnings.append("Bundle has no entries")
    return Validation(valid=not errors, resource_type=rt, errors=errors, warnings=warnings)


@mcp.tool()
def govern_phi(message_or_fhir: str) -> PHIGovernance:
    """Governance pass: detect PHI, surface HIPAA/MDR risk + data-minimisation advice (attestable for CSOAI)."""
    _sigil("G", "hl7-fhir|govern_phi")
    present: List[str] = []
    low = message_or_fhir.lower()
    for field, key in [("patient name", "pid|"), ("date of birth", "birthdate"), ("patient id", "resourcetype")]:
        pass
    p = None
    try:
        p = parse_hl7v2(message_or_fhir) if "MSH" in message_or_fhir else None
    except Exception:
        p = None
    if p:
        if p.patient_name: present.append("patient_name")
        if p.dob: present.append("date_of_birth")
        if p.patient_id: present.append("patient_id")
    else:
        if '"name"' in low: present.append("patient_name")
        if "birthdate" in low: present.append("date_of_birth")
    flags = []
    if present:
        flags.append(f"PHI present ({', '.join(present)}) — encrypt in transit + at rest; minimum-necessary access")
    return PHIGovernance(
        phi_fields_present=present,
        risk_flags=flags,
        frameworks=["HIPAA", "EU MDR/IVDR", "EU AI Act Art. 6(1)/Annex I", "GDPR Art. 9 (health data)"],
        minimisation_advice="Strip identifiers not required downstream; pseudonymise where possible; log access.",
        attestable=True,
    )


def main():
    mcp.run()


if __name__ == "__main__":
    main()
