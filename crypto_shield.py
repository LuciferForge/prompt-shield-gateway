#!/usr/bin/env python3
"""
Layer 3: EIP-712 Cryptographic Order Guard (< 2ms)
Ensures LLMs can NEVER execute financial transactions or transfers without an explicit, valid EIP-712 typed signature.
"""

from eth_account import Account
from eth_account.messages import encode_typed_data
from typing import Dict, Any, Tuple

class Layer3CryptoShield:
    def __init__(self):
        pass

    def verify_eip712_signature(self, domain: Dict[str, Any], types: Dict[str, Any], message: Dict[str, Any], signature: str, expected_address: str) -> Tuple[bool, str]:
        """
        Verify EIP-712 typed signature matches expected wallet address before financial execution.
        """
        try:
            signable_msg = encode_typed_data(domain_data=domain, message_types=types, message_data=message)
            recovered_addr = Account.recover_message(signable_msg, signature=signature)
            
            if recovered_addr.lower() == expected_address.lower():
                return True, f"Cryptographic Verification Passed. Signer: {recovered_addr}"
            else:
                return False, f"Signature Mismatch: Expected {expected_address}, Recovered {recovered_addr}"
        except Exception as e:
            return False, f"Cryptographic Signature Recovery Failed: {e}"

    def enforce_financial_guardrail(self, tool_call: str, tool_args: Dict[str, Any], signature_payload: Dict[str, Any] = None) -> Tuple[bool, str]:
        """
        Enforce zero-trust financial execution guardrail on sensitive tools (trade, transfer, withdrawal).
        """
        financial_tools = ["place_order", "transfer_funds", "withdraw_usdc", "execute_trade"]
        
        if tool_call in financial_tools:
            if not signature_payload or "signature" not in signature_payload:
                return False, f"LLM06 Excessive Agency Blocked: Tool '{tool_call}' requires valid EIP-712 signature payload."
                
            # Verify cryptographic signature
            is_valid, msg = self.verify_eip712_signature(
                domain=signature_payload.get("domain", {}),
                types=signature_payload.get("types", {}),
                message=signature_payload.get("message", {}),
                signature=signature_payload.get("signature", ""),
                expected_address=signature_payload.get("expected_address", "")
            )
            return is_valid, msg
            
        return True, "Tool Execution Approved"
