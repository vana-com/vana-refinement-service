#!/usr/bin/env python3
import os
import json
import secrets
from typing import List, Dict, Any, Optional
import asyncio

import httpx
from dotenv import load_dotenv
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
import argparse
import os

# Initialize environment
load_dotenv()

# API client setup
class PhalaCVMClient:
    def __init__(
            self,
            base_url: str = "https://cloud-api.phala.network/api/v1",
            timeout: float = 60.0
    ):
        self.base_url = base_url
        self.client = httpx.Client(
            base_url=base_url,
            headers={
                'Content-Type': 'application/json',
                'x-api-key': os.getenv('PHALA_CLOUD_API_KEY'),
            },
            timeout=timeout
        )

    def get_pubkey(self, vm_config: Dict[str, Any]) -> Dict[str, str]:
        response = self.client.post("/cvms/pubkey/from_cvm_configuration", json=vm_config)
        response.raise_for_status()
        return response.json()

    def create_vm(self, config: Dict[str, Any]) -> Dict[str, Any]:
        """Create a VM in Phala Cloud with detailed error logging."""
        print("Sending VM creation request to Phala Cloud...")
        response = self.client.post("/cvms/from_cvm_configuration", json=config)

        try:
            response.raise_for_status()
            return response.json()
        except httpx.HTTPStatusError as e:
            print(f"HTTP Error Status: {e.response.status_code}")
            print(f"Full error response: {e.response.text}")

            # Try to parse the error response as JSON for more details
            try:
                error_details = e.response.json()
                print(f"Error details: {json.dumps(error_details, indent=2)}")
            except:
                print("Error response is not valid JSON")
            raise

    def list_vms(self) -> List[Dict[str, Any]]:
        response = self.client.get("/cvms")
        response.raise_for_status()
        return response.json()

    def get_vm_details(self, vm_id: str) -> Dict[str, Any]:
        """Get details of a specific VM."""
        response = self.client.get(f"/cvms/{vm_id}")
        response.raise_for_status()
        return response.json()

    def get_vm_compose(self, vm_id: str) -> Dict[str, Any]:
        """Get the compose manifest of a VM."""
        response = self.client.get(f"/cvms/{vm_id}/compose")
        response.raise_for_status()
        return response.json()

    def update_vm_compose(
            self,
            vm_id: str,
            compose_manifest: Dict[str, Any],
            encrypted_env: Optional[str] = None,
            timeout: float = 120.0
    ) -> Dict[str, Any]:
        """Update a VM's compose manifest"""
        body = {"compose_manifest": compose_manifest}
        if encrypted_env:
            body["encrypted_env"] = encrypted_env

        print(f"Sending update request for VM {vm_id}...")

        try:
            response = self.client.put(
                f"/cvms/{vm_id}/compose",
                json=body,
                timeout=timeout
            )
            response.raise_for_status()
            print(f"VM update request completed successfully")
            return response.json()
        except httpx.ReadTimeout:
            # If we get a timeout, check if the update was successful
            print("Update request timed out but may have been accepted by the server.")
            print(f"Checking status of VM {vm_id}...")

            # Wait a moment before checking status
            import time
            time.sleep(2)

            # Check VM status
            try:
                vm_details = self.get_vm_details(vm_id)
                if vm_details.get("status") in ["Running", "Updating", "Accepted"]:
                    print(f"VM status is '{vm_details.get('status')}'. The update appears to be in progress or completed.")
                    return {"status": "Accepted", "message": "Update request accepted", "vm_id": vm_id}
                else:
                    print(f"VM has status: {vm_details.get('status')}. The update may not have been processed.")
            except Exception as check_error:
                print(f"Error checking VM status after timeout: {str(check_error)}")

            # Return a custom response with enough information to continue
            return {
                "status": "Unknown",
                "message": "Update request timed out but may have been accepted. Check VM status manually.",
                "vm_id": vm_id
            }
        except httpx.HTTPStatusError as e:
            print(f"HTTP Error Status: {e.response.status_code}")
            print(f"Full error response: {e.response.text}")

            # Try to parse the error response as JSON for more details
            try:
                error_details = e.response.json()
                print(f"Error details: {json.dumps(error_details, indent=2)}")
            except:
                print("Error response is not valid JSON")
            raise

    def get_available_teepods(self) -> Dict[str, Any]:
        """Get list of available Teepods from Phala Cloud."""
        print("Requesting available Teepods from Phala Cloud...")
        response = self.client.get("/teepods/available")
        response.raise_for_status()
        return response.json()

# Helper functions
def encrypt_env_vars(envs: List[Dict[str, str]], public_key_hex: str) -> str:
    """
    Encrypt environment variables for Phala Cloud.

    Args:
        envs: List of environment variables to encrypt
        public_key_hex: Public key hex string for encryption

    Returns:
        Hex string of encrypted environment variables
    """
    # Convert environment variables to JSON
    envs_json = json.dumps({"env": envs})

    # Generate private key and get public key
    private_key = x25519.X25519PrivateKey.generate()
    public_key = private_key.public_key()
    my_public_bytes = public_key.public_bytes_raw()

    # Convert remote public key from hex and create public key object
    remote_public_key_bytes = bytes.fromhex(public_key_hex.replace("0x", ""))
    remote_public_key = x25519.X25519PublicKey.from_public_bytes(remote_public_key_bytes)

    # Generate shared key
    shared_key = private_key.exchange(remote_public_key)

    # Generate random IV (12 bytes for AES-GCM)
    iv = secrets.token_bytes(12)

    # Encrypt data
    aesgcm = AESGCM(shared_key)
    encrypted_data = aesgcm.encrypt(iv, envs_json.encode(), None)

    # Combine all components: sender public key + IV + ciphertext
    result = my_public_bytes + iv + encrypted_data
    return result.hex()

def read_docker_compose(file_path: str, docker_tag: str = "latest") -> str:
    """Read Docker Compose file and replace variables."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()

        # Replace tag variable if present
        content = content.replace('${DOCKER_TAG}', docker_tag)

        return content
    except FileNotFoundError:
        raise FileNotFoundError(f"Docker Compose file not found at {file_path}. Please create this file before running the deployment.")

def read_pre_launch_script(file_path: str) -> str:
    """Read pre-launch script file."""
    try:
        with open(file_path, 'r') as f:
            content = f.read()
        return content
    except FileNotFoundError:
        raise FileNotFoundError(f"Pre-launch script file not found at {file_path}. Please create this file before running the deployment.")

async def deploy(
        teepod_id: int,
        image: str,
        vm_name: str,
        vm_id: Optional[str] = None,
        docker_compose_file: str = "docker-compose-tee-phala-cloud.yml",
        docker_tag: str = "latest",
        update_existing: bool = True, # Keep this flag to control update behavior when vm_id is provided
        timeout: float = 120.0,
        vcpu: int = 2,
        memory: int = 8192,
        disk_size: int = 40,
        env_vars_to_encrypt: List[Dict[str, str]] = None,
) -> Dict[str, Any]:
    """Deploy a VM to Phala Cloud or update an existing one if vm_id is provided."""

    # Read Docker Compose configuration from file
    docker_compose = read_docker_compose(docker_compose_file, docker_tag)
    pre_launch_script = read_pre_launch_script("prelaunch.sh")
    print(f"Using Docker tag: {docker_tag}")

    vm_config = {
        "name": vm_name,
        "compose_manifest": {
            "name": vm_name,
            "docker_compose_file": docker_compose,
            "pre_launch_script": pre_launch_script,
        },
        "vcpu": vcpu,
        "memory": memory,
        "disk_size": disk_size,
        "teepod_id": teepod_id,
        "image": image,
        "advanced_features": {
            "tproxy": True,
            "kms": True,
            "public_sys_info": True,
            "public_logs": False,
            "docker_config": {
                "password": "",
                "registry": None,
                "username": "",
            },
            "listed": False,
        }
    }

    # Check for required API key
    if not os.getenv("PHALA_CLOUD_API_KEY"):
        raise ValueError("Missing required environment variable: PHALA_CLOUD_API_KEY")

    # Create client with the specified timeout
    client = PhalaCVMClient(timeout=timeout)

    # If a specific VM ID is provided, update it
    if vm_id:
        if update_existing:
            print(f"Updating VM with ID {vm_id}...")
            # Get the existing VM's compose settings to retrieve its public key
            try:
                vm_compose = client.get_vm_compose(vm_id)
            except httpx.HTTPStatusError as e:
                print(f"Failed to get compose details for VM {vm_id}: {e}")
                raise ValueError(f"Could not retrieve details for VM ID {vm_id}. Ensure it exists and is accessible.")

            # Create a properly structured compose manifest for the update
            compose_manifest = {
                "name": vm_name, # Allow name update if needed
                "docker_compose_file": docker_compose,
                "pre_launch_script": pre_launch_script,
            }

            # Encrypt environment variables using the existing VM's pubkey
            encrypted_env = None
            if env_vars_to_encrypt:
                encrypted_env = encrypt_env_vars(
                    env_vars_to_encrypt,
                    vm_compose["env_pubkey"],
                )

            print("Manifest for update:")
            print(json.dumps(compose_manifest, indent=2))

            # Update the VM with the longer timeout
            response = client.update_vm_compose(
                vm_id,
                compose_manifest,
                encrypted_env,
                timeout=timeout
            )

            if response.get("status") in ["Accepted", "Unknown"]: # Handle timeout case
                print(f"VM with ID {vm_id} update initiated successfully (status: {response.get('status')}).")
            else:
                print(f"VM update failed with status: {response.get('status')}")
                print(json.dumps(response, indent=2))
            return response
        else:
            # If vm_id is provided but update is disabled, treat it as a skip
            print(f"VM ID {vm_id} provided, but update flag is not set. Skipping.")
            return {"status": "skipped", "message": f"Update skipped for VM {vm_id}", "id": vm_id}

    # If no vm_id is provided, create a new VM
    print(f"Creating new VM {vm_name}...")

    # Step 1: Get encryption public key for the new VM config
    with_pubkey = client.get_pubkey(vm_config)

    # Step 2: Encrypt environment variables if provided
    encrypted_env = None
    if env_vars_to_encrypt:
        encrypted_env = encrypt_env_vars(
            env_vars_to_encrypt,
            with_pubkey["app_env_encrypt_pubkey"],
        )

    # Step 3: Create VM with encrypted environment variables
    create_payload = {
        **vm_config,
        "app_env_encrypt_pubkey": with_pubkey["app_env_encrypt_pubkey"],
        "app_id_salt": with_pubkey["app_id_salt"],
    }
    if encrypted_env:
        create_payload["encrypted_env"] = encrypted_env

    print("Manifest for creation:")
    print(json.dumps(create_payload, indent=2))

    response = client.create_vm(create_payload)
    print(f"VM {vm_name} creation initiated.")
    return response

async def main():
    parser = argparse.ArgumentParser(description='Deploy or update a VM on Phala Cloud')
    parser.add_argument('--teepod-id', type=int, default=3, help='Teepod ID to deploy to (default: 3)')
    parser.add_argument('--image', type=str, default="dstack-dev-0.3.5", help='Phala VM image name (default: dstack-dev-0.3.5)')
    parser.add_argument('--vm-name', type=str, help='Name for the VM (defaults to env var PHALA_VM_NAME or "test-api")')
    parser.add_argument('--vm-id', type=str, help='Specific VM ID to update (if provided, updates this VM; otherwise creates a new one; defaults to env var PHALA_VM_ID)')
    parser.add_argument('--update', action='store_true', help='Allow updating if --vm-id is provided (default: False, unless --vm-id is set)')
    parser.add_argument('--docker-tag', type=str, default="latest", help='Docker image tag to use in compose file (default: latest)')
    parser.add_argument('--docker-compose-file', type=str, default="docker-compose-tee-phala-cloud.yml",
                        help='Path to Docker Compose file (default: docker-compose-tee-phala-cloud.yml)')
    parser.add_argument('--list-teepods', action='store_true', help='List available Teepods and exit')
    parser.add_argument('--list-vms', action='store_true', help='List all VMs and exit')
    parser.add_argument('--timeout', type=float, default=120.0, help='Timeout in seconds for API requests (default: 120)')
    parser.add_argument('--vcpu', type=int, default=2, help='Number of virtual CPUs (default: 2)')
    parser.add_argument('--memory', type=int, default=8192, help='Memory in MB (default: 8192)')
    parser.add_argument('--disk-size', type=int, default=40, help='Disk size in GB (default: 40)')
    parser.add_argument('--env-file', type=str, help='Path to .env file containing environment variables to encrypt')
    parser.add_argument('--env', action='append', help='Environment variable to encrypt (KEY=VALUE format)', default=[])
    parser.add_argument('--auto-env', action='store_true', default=True, help='Automatically encrypt all environment variables (default: True)')
    parser.add_argument('--include-env', action='append', help='Explicitly include these environment variables (if auto-env is used)', default=[])
    parser.add_argument('--exclude-env', action='append', help='Exclude these environment variables (if auto-env is used)', default=[])
    parser.add_argument('--list-env', action='store_true', help='List environment variables that would be encrypted and exit')

    args = parser.parse_args()

    # Create client with the specified timeout
    client = PhalaCVMClient(timeout=args.timeout)

    # Option to just list Teepods and exit
    if args.list_teepods:
        teepods = client.get_available_teepods()
        print("Available Teepods:")
        print(json.dumps(teepods, indent=2))
        return teepods

    # Option to list all VMs and exit
    if args.list_vms:
        vms = client.list_vms()
        print("Available VMs:")
        if not vms:
            print("No VMs found.")
        else:
            for vm in vms:
                print(f"ID: {vm.get('id')} | Name: {vm.get('name')} | Status: {vm.get('status')}")
        return vms

    # Parse environment variables to encrypt
    env_vars_to_encrypt = []
    env_keys_added = set() # Keep track of keys to avoid duplicates

    def add_env_var(key, value):
        if key not in env_keys_added:
            env_vars_to_encrypt.append({"key": key, "value": value})
            env_keys_added.add(key)

    # Add variables from --env arguments first (higher priority)
    for env_str in args.env:
        if '=' in env_str:
            key, value = env_str.split('=', 1)
            add_env_var(key, value)
        else:
            print(f"Warning: Skipping incorrectly formatted --env variable: {env_str}")

    # Add variables from env file if specified
    if args.env_file:
        try:
            with open(args.env_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#') and '=' in line:
                        key, value = line.split('=', 1)
                        add_env_var(key, value)
        except Exception as e:
            print(f"Error reading environment file {args.env_file}: {str(e)}")
            raise

    # Automatically use system environment variables if auto-env is set
    if args.auto_env:
        print("Automatically collecting environment variables...")
        # Exclude common system variables and CI-related variables
        default_exclusions = {
            'PATH', 'HOME', 'USER', 'SHELL', 'PWD', 'OLDPWD', 'TERM',
            'SHLVL', 'HOSTNAME', 'PHALA_CLOUD_API_KEY', '_',
            'PYTHONPATH', 'LANG', 'LC_ALL', 'LESSOPEN', 'LESSCLOSE',
            'CI', 'GITHUB_ACTIONS', 'RUNNER_OS', 'RUNNER_ARCH', 'RUNNER_NAME',
            'AGENT_OS', 'AGENT_MACHINETYPE', 'AGENT_VERSION',
            'SYSTEM_TEAMFOUNDATIONCOLLECTIONURI', 'SYSTEM_TEAMPROJECT',
            'BUILD_BUILDID', 'BUILD_BUILDNUMBER', 'BUILD_REPOSITORY_NAME',
            'BUILD_SOURCEBRANCHNAME', 'BUILD_REASON',
        }
        exclusions = default_exclusions.union(set(args.exclude_env))
        env_dict = dict(os.environ)
        included_vars_auto = []

        if args.include_env:
            print(f"Including only specifically requested variables via --include-env: {args.include_env}")
            for key in args.include_env:
                if key in env_dict and key not in exclusions:
                    add_env_var(key, env_dict[key])
                    included_vars_auto.append(key)
        else:
            for key, value in env_dict.items():
                # Skip exclusions and common CI/runner prefixes
                if key not in exclusions and not key.startswith(('GITHUB_', 'RUNNER_', 'AGENT_', 'SYSTEM_', 'BUILD_')):
                    add_env_var(key, value)
                    included_vars_auto.append(key)

        print(f"Automatically included {len(included_vars_auto)} environment variables (after exclusions and explicit includes/overrides).")

        if args.list_env: # Show auto-included vars if listing
            print("Variables automatically included (after filtering):")
            for var in included_vars_auto:
                value = env_dict[var]
                display_value = value[:5] + "..." + value[-2:] if len(value) > 10 else value[:2] + "***"
                print(f"  {var}={display_value}")

    # Option to just list environment variables and exit
    if args.list_env:
        print(f"\nFinal list of environment variables to be encrypted ({len(env_vars_to_encrypt)} total):")
        if not env_vars_to_encrypt:
            print("  (None)")
        else:
            for item in env_vars_to_encrypt:
                key = item['key']
                value = item['value']
                display_value = value[:5] + "..." + value[-2:] if len(value) > 10 else value[:2] + "***"
                print(f"  {key}={display_value}")
        return {"status": "list_env_only", "env_count": len(env_vars_to_encrypt)}

    # Print final count of environment variables being encrypted
    print(f"Will encrypt {len(env_vars_to_encrypt)} environment variables for the VM.")

    try:
        # Get VM name from args or environment variable
        vm_name = args.vm_name if args.vm_name else os.getenv('PHALA_VM_NAME', 'test-api')
        # Get VM ID from args or environment variable
        vm_id = args.vm_id if args.vm_id else os.getenv('PHALA_VM_ID')

        # Note:
        # If vm_id is provided, --update is implicitly True unless explicitly denied
        # If vm_id is not provided, --update has no effect
        update_flag = args.update or bool(vm_id)

        print(f"Target VM Name: {vm_name}")
        if vm_id:
            print(f"Target VM ID: {vm_id} (implies update)")
        else:
            print("No VM ID provided, will create a new VM.")

        # Proceed with deployment or update
        response = await deploy(
            teepod_id=args.teepod_id,
            image=args.image,
            vm_name=vm_name,
            vm_id=vm_id,
            docker_compose_file=args.docker_compose_file,
            docker_tag=args.docker_tag,
            update_existing=update_flag, # Use derived update flag
            timeout=args.timeout,
            vcpu=args.vcpu,
            memory=args.memory,
            disk_size=args.disk_size,
            env_vars_to_encrypt=env_vars_to_encrypt,
        )

        if response.get("status") == "Unknown":
            print('\nOperation completed with timeout, but may have succeeded:')
            print(json.dumps(response, indent=2))
            print('Please check the VM status in Phala Cloud UI')
        elif response.get("status") == "skipped":
            print('\nOperation skipped:')
            print(json.dumps(response, indent=2))
        else:
            print('\nOperation successful or initiated:', json.dumps(response, indent=2))

        return response
    except Exception as error:
        import traceback
        print('\nOperation failed:', str(error))
        # print(traceback.format_exc()) # Uncomment for full traceback if needed
        raise

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except Exception:
        # Catch exception raised from main to prevent non-zero exit code unless needed
        # print("Exiting due to error.") # Error is already printed in main's exception handler
        exit(1) # Exit with error code if main fails
