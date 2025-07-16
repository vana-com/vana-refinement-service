from eth_account.messages import encode_defunct
from eth_account import Account
from web3 import Web3
import json
import logging
import os
from dotenv import load_dotenv
from typing import Tuple
from fastapi import HTTPException
import vana


# Load environment variables
load_dotenv()

# Web3 setup
BLOCKCHAIN_HTTP_URL = os.getenv("CHAIN_NETWORK_ENDPOINT", "https://rpc.moksha.vana.org")

# Load Data Refiner Registry ABI for refiner owner verification
try:
    # Try to load ABI from vana client config
    config = vana.Config()
    chain_manager = vana.ChainManager(config=config)
    
    # Get the Data Refiner Registry ABI from vana client
    DATA_REFINER_REGISTRY_ABI = chain_manager.data_refiner_registry_contract.abi
    DATA_REFINER_REGISTRY_CONTRACT_ADDRESS = chain_manager.data_refiner_registry_contract.address
    
    logging.info(f"Successfully loaded Data Refiner Registry ABI from vana client")
except Exception as e:
    logging.error(f"Failed to load Data Refiner Registry ABI from vana client: {e}")
    # Fallback to empty ABI
    DATA_REFINER_REGISTRY_ABI = []
    DATA_REFINER_REGISTRY_CONTRACT_ADDRESS = None

# Initialize Web3 connection
try:
    w3 = Web3(Web3.HTTPProvider(BLOCKCHAIN_HTTP_URL))
    if not w3.is_connected():
        logging.warning(f"Failed to connect to blockchain at {BLOCKCHAIN_HTTP_URL}")
        w3 = None
        data_refiner_registry_contract = None
    else:
        logging.info(f"Successfully connected to blockchain at {BLOCKCHAIN_HTTP_URL}")
        if DATA_REFINER_REGISTRY_CONTRACT_ADDRESS and DATA_REFINER_REGISTRY_ABI:
            data_refiner_registry_contract = w3.eth.contract(
                address=Web3.to_checksum_address(DATA_REFINER_REGISTRY_CONTRACT_ADDRESS),
                abi=DATA_REFINER_REGISTRY_ABI
            )
        else:
            data_refiner_registry_contract = None
except Exception as e:
    logging.error(f"Error initializing Web3: {e}")
    w3 = None
    data_refiner_registry_contract = None

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


def get_refiner_owner(refiner_id: int) -> str:
    """
    Get the owner address of a refiner from the Data Refiner Registry contract.
    
    Args:
        refiner_id: The ID of the refiner
        
    Returns:
        The owner address of the refiner, or empty string if not found
    """    
    if not w3 or not data_refiner_registry_contract:
        logging.error("Cannot verify refiner owner: blockchain connection or Data Refiner Registry contract not available")
        return ""
    
    try:
        # Get refiner info from the Data Refiner Registry contract
        # The refiners() function returns a RefinerInfo struct with: (dlpId, owner, name, schemaDefinitionUrl, refinementInstructionUrl)
        refiner_info = data_refiner_registry_contract.functions.refiners(refiner_id).call()
        # The owner address is the second field (index 1) in the refiner struct
        owner_address = refiner_info[1] if len(refiner_info) > 1 else ""
        
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


def verify_refiner_access(refiner_id: int, signature: str) -> str:
    """
    Verify that the requester has access to the refiner's statistics.
    
    Args:
        refiner_id: The ID of the refiner
        signature: The signature to verify
        
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
    refiner_owner = get_refiner_owner(refiner_id)
    if not refiner_owner:
        logger.error(f"Could not determine owner for refiner {refiner_id}")
        raise HTTPException(status_code=500, detail="Could not verify refiner ownership")
    
    if requester_address.lower() != refiner_owner.lower():
        logger.warning(f"Access denied: {requester_address} is not the owner of refiner {refiner_id} (owner: {refiner_owner})")
        raise HTTPException(status_code=403, detail="Access denied: You are not the owner of this refiner")
    
    logger.info(f"Refiner owner {requester_address} accessing refiner {refiner_id} stats")
    return requester_address 