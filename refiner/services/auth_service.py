from eth_account.messages import encode_defunct
from eth_account import Account
import logging
import os
from dotenv import load_dotenv
from typing import Tuple, Optional
from fastapi import HTTPException
import vana


# Load environment variables
load_dotenv()

# Admin wallet configuration for API authentication
ADMIN_WALLET_WHITELIST = []
admin_whitelist_env = os.getenv("ADMIN_WALLET_WHITELIST", "")
if admin_whitelist_env:
    ADMIN_WALLET_WHITELIST = [addr.lower().strip() for addr in admin_whitelist_env.split(",") if addr.strip()]
    logging.info(f"Admin wallet whitelist configured with {len(ADMIN_WALLET_WHITELIST)} addresses")

# Legacy single admin address support - add to whitelist if provided
legacy_admin_address = os.getenv("ADMIN_WALLET_ADDRESS")
if legacy_admin_address:
    legacy_admin_address = legacy_admin_address.lower().strip()
    if legacy_admin_address not in ADMIN_WALLET_WHITELIST:
        ADMIN_WALLET_WHITELIST.append(legacy_admin_address)
        logging.info(f"Added ADMIN_WALLET_ADDRESS to admin whitelist: {legacy_admin_address}")

if not ADMIN_WALLET_WHITELIST:
    logging.warning("No admin wallets configured. Admin endpoints will not be functional.")
else:
    logging.info(f"Total admin wallets configured: {len(ADMIN_WALLET_WHITELIST)}")


def verify_signature(signature: str, message: str) -> Tuple[bool, str]:
    """
    Verify an Ethereum signature of the message and return the address that signed it.

    Args:
        signature: The signature to verify.
        message: The message that was signed.

    Returns:
        Tuple of (is_valid, address)
    """
    try:
        # For debugging purposes
        logging.info(f"Verifying signature for message: {message}")

        message_hash = encode_defunct(text=message)

        # Recover the signer's address from the signature
        address = Account.recover_message(message_hash, signature=signature)

        # Print recovered address for debugging
        logging.info(f"Recovered address: {address}")

        # Convert address to lowercase for comparison
        address = address.lower()

        # In production mode, we just verify the signature is valid
        # The permission check will happen separately
        return True, address

    except Exception as e:
        logging.error(f"Signature verification error: {e}", exc_info=True)
        return False, ""


def get_refiner_owner(refiner_id: int, vana_client: vana.Client) -> str:
    """
    Get the owner address of a refiner from the Data Refiner Registry contract using the vana client.
    
    Args:
        refiner_id: The ID of the refiner
        vana_client: The vana client instance
        
    Returns:
        The owner address of the refiner, or empty string if not found
    """
    if not vana_client:
        logging.error("Cannot verify refiner owner: vana client not available")
        return ""
    
    try:
        # Get refiner info from the vana client
        refiner_info = vana_client.get_refiner(refiner_id)
        if not refiner_info:
            logging.warning(f"Refiner {refiner_id} not found")
            return ""
        
        # Extract the owner address from the refiner info
        owner_address = refiner_info.get('owner', '')
        
        logging.info(f"Refiner {refiner_id} owner: {owner_address}")
        return owner_address.lower() if owner_address else ""
        
    except Exception as e:
        logging.error(f"Error getting refiner owner for refiner {refiner_id}: {e}")
        return ""


def is_admin_wallet(address: str) -> bool:
    """
    Check if an address is in the admin wallet whitelist.
    
    Args:
        address: The wallet address to check
        
    Returns:
        True if the address is an admin wallet, False otherwise
    """
    return address.lower() in ADMIN_WALLET_WHITELIST


def verify_refiner_access(refiner_id: int, signature: str, vana_client: vana.Client) -> str:
    """
    Verify that the requester has access to the refiner's statistics.
    
    Args:
        refiner_id: The ID of the refiner
        signature: The signature to verify
        vana_client: The vana client instance
        
    Returns:
        The verified requester address
        
    Raises:
        HTTPException: If verification fails
    """
    logger = logging.getLogger(__name__)
    
    # Verify the signature against the refiner_id as a string
    message_to_sign = str(refiner_id)
    is_valid, requester_address = verify_signature(signature, message_to_sign)
    
    if not is_valid:
        logger.warning(f"Invalid signature for refiner {refiner_id} access request")
        raise HTTPException(status_code=403, detail="Invalid signature or unauthorized access")
    
    # Check if the address is an admin wallet
    if is_admin_wallet(requester_address):
        logger.info(f"Admin wallet {requester_address} accessing refiner {refiner_id} stats")
        return requester_address
    
    # Check if the address is the refiner owner
    refiner_owner = get_refiner_owner(refiner_id, vana_client)
    if not refiner_owner:
        logger.error(f"Could not determine owner for refiner {refiner_id}")
        raise HTTPException(status_code=500, detail="Could not verify refiner ownership")
    
    if requester_address.lower() != refiner_owner.lower():
        logger.warning(f"Access denied: {requester_address} is not the owner of refiner {refiner_id} (owner: {refiner_owner})")
        raise HTTPException(status_code=403, detail="Access denied: You are not the owner of this refiner")
    
    logger.info(f"Refiner owner {requester_address} accessing refiner {refiner_id} stats")
    return requester_address 