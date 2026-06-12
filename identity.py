"""
Identity Layer — DID generation and Verifiable Credential issuance/verification.
Encryption: SHA256 for credential hashing.
"""

import uuid
import hashlib
import json
from datetime import datetime
from typing import Tuple, Dict, Optional


class IdentityManager:
    def __init__(self, db):
        self.db = db

    def generate_did(self) -> str:
        return f"did:example:{uuid.uuid4()}"

    def issue_verifiable_credential(self, did: str, agent_name: str, role: str) -> Dict:
        credential = {
            "@context": ["https://www.w3.org/2018/credentials/v1"],
            "type": ["VerifiableCredential", "AIAgentCredential"],
            "issuer": "did:example:framework-issuer",
            "issuanceDate": datetime.now().isoformat(),
            "encryption": "SHA256",
            "credentialSubject": {
                "id": did,
                "agent_name": agent_name,
                "role": role,
                "framework_version": "2.0"
            }
        }
        credential_json = json.dumps(credential, sort_keys=True)
        credential_hash = hashlib.sha256(credential_json.encode()).hexdigest()
        credential["credential_hash"] = credential_hash
        return credential

    def register_agent(self, agent_name: str, role: str) -> Tuple[str, Dict]:
        did = self.generate_did()
        vc = self.issue_verifiable_credential(did, agent_name, role)
        credential_hash = vc["credential_hash"]
        credential_json = json.dumps(vc, sort_keys=True)
        self.db.create_agent(did, agent_name, role)
        self.db.create_credential(did, credential_json, credential_hash)
        return did, vc

    def verify_credential(self, did: str, credential_hash: str) -> bool:
        return self.db.verify_credential(did, credential_hash)

    def get_agent_role(self, did: str) -> Optional[str]:
        return self.db.get_agent_role(did)
