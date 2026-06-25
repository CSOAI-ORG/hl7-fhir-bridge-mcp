import sys,os
sys.path.insert(0,os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import server

H="MSH|^~\\&|EPIC|HOSP|REC|FAC|20260625||ADT^A01|MSG1|P|2.5\rPID|1||MRN1^^^HOSP||DOE^JOHN||19800101|M"
def test_parse():
    p=server.parse_hl7v2(H); assert p.message_type=="ADT"; assert p.patient_id=="MRN1"
def test_fhir():
    assert server.hl7_to_fhir(H)["resourceType"]=="Bundle"
def test_phi():
    assert "patient_id" in server.govern_phi(H).phi_fields_present
