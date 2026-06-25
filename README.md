# HL7 / FHIR Bridge MCP

mcp-name: io.github.CSOAI-ORG/hl7-fhir-bridge-mcp

Part of the **CSOAI Layer-0 legacy-bridge family** (sibling of `cobol-bridge-mcp`). Bridges healthcare legacy messaging (HL7 v2 pipe-delimited) and modern **FHIR** to ONE OS / CSOAI, and **governs PHI**.

## Tools
- `parse_hl7v2(message)` — message type + key patient fields from a pipe-delimited HL7 v2 message.
- `hl7_to_fhir(message)` — map HL7 v2 → a minimal FHIR R4 message Bundle (Patient + MessageHeader).
- `validate_fhir(resource_json)` — well-formed JSON + resourceType + basic shape.
- `govern_phi(message_or_fhir)` — detect PHI, surface HIPAA/MDR/GDPR-Art.9 risk + data-minimisation advice; attestable on the CSOAI ledger.

## Run
```bash
pip install -e .
python server.py        # stdio MCP server
```

The win: legacy HL7 / FHIR clinical data → CSOAI PHI governance/attestation → ONE OS. Pairs with `hipaa-compliance-mcp` + `healthcare-ai-governance-mcp` + `eu-ai-act-compliance-mcp` (Annex I medical devices).
