#!/bin/bash
echo "----------------------------------------------"
echo "Running Phala Cloud Pre-Launch Script v0.0.3 with enhanced diagnostic logging"
echo "This script will now log detailed disk usage before and after cleanup."
echo "----------------------------------------------"
set -e

# Function to log the current state of disk usage for diagnostics.
log_disk_state() {
    TITLE=$1
    echo ""
    echo "============================================================"
    echo "  DISK USAGE REPORT: $TITLE"
    echo "============================================================"

    echo ""
    echo "--- Overall Filesystem Usage (df -h) ---"
    df -h
    echo ""

    echo "--- Docker System-Wide Usage (docker system df -v) ---"
    # Use -v for verbose output to see all items, not just reclaimable space.
    docker system df -v
    echo ""

    echo "--- Top 20 Largest Items in /var/lib/docker (du) ---"
    echo "(This may take a moment...)"
    # This command finds the largest files/directories, helping to pinpoint the exact source of bloat.
    du -ah /var/lib/docker 2>/dev/null | sort -rh | head -n 20
    echo ""

    echo "--- Summary of /tmp directory usage ---"
    du -sh /tmp
    echo ""

    echo "==================== END REPORT: $TITLE ===================="
    echo ""
}

# Function: Perform a comprehensive Docker and system cleanup
perform_cleanup() {
    echo "--- Starting comprehensive cleanup of temporary artifacts ---"

    # 1. Clean up old system temporary files from previous crashed runs.
    # The application uses tempfile.mkdtemp() which creates directories like /tmp/tmpXXXXXX.
    # We find directories in /tmp matching this pattern that are older than 60 minutes and remove them.
    # This is safer than `rm -rf /tmp/tmp*` and the time buffer prevents deleting files from a process that just started.
    echo "Cleaning up orphaned temporary directories in /tmp..."
    find /tmp -name "tmp*" -type d -mmin +60 -exec rm -rf {} +
    echo "System temporary file cleanup complete."

    # 2. Prune all stopped Docker containers.
    # This is safe to run on startup as no application containers should be running yet.
    echo "Pruning stopped Docker containers..."
    docker container prune -f

    # 3. Prune the Docker builder cache.
    echo "Pruning Docker builder cache..."
    docker builder prune -af

    # 4. Prune dangling and unused Docker images.
    echo "Pruning unused images..."
    docker image prune -af

    # 5. Prune all unused Docker volumes.
    echo "Pruning unused volumes..."
    docker volume prune -f

    echo "--- Comprehensive cleanup finished ---"
}


# Function: Check Docker login status without exposing credentials
check_docker_login() {
    # Try to verify login status without exposing credentials
    if docker info 2>/dev/null | grep -q "Username"; then
        return 0
    else
        return 1
    fi
}

# Function: Check AWS ECR login status
check_ecr_login() {
    # Check if we can access the registry without exposing credentials
    if aws ecr get-authorization-token --region $DSTACK_AWS_REGION &>/dev/null; then
        return 0
    else
        return 1
    fi
}

# Main logic starts here
echo "Starting login process..."

# Check if Docker credentials exist
if [[ -n "$DSTACK_DOCKER_USERNAME" && -n "$DSTACK_DOCKER_PASSWORD" ]]; then
    echo "Docker credentials found"

    # Check if already logged in
    if check_docker_login; then
        echo "Already logged in to Docker registry"
    else
        echo "Logging in to Docker registry..."
        # Login without exposing password in process list
        if [[ -n "$DSTACK_DOCKER_REGISTRY" ]]; then
            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin "$DSTACK_DOCKER_REGISTRY"
        else
            echo "$DSTACK_DOCKER_PASSWORD" | docker login -u "$DSTACK_DOCKER_USERNAME" --password-stdin
        fi

        if [ $? -eq 0 ]; then
            echo "Docker login successful"
        else
            echo "Docker login failed"
            exit 1
        fi
    fi
# Check if AWS ECR credentials exist
elif [[ -n "$DSTACK_AWS_ACCESS_KEY_ID" && -n "$DSTACK_AWS_SECRET_ACCESS_KEY" && -n "$DSTACK_AWS_REGION" && -n "$DSTACK_AWS_ECR_REGISTRY" ]]; then
    echo "AWS ECR credentials found"

    # Check if AWS CLI is installed
    if ! command -v aws &> /dev/null; then
        echo "AWS CLI not installed, installing..."
        curl "https://awscli.amazonaws.com/awscli-exe-linux-x86_64-2.24.14.zip" -o "awscliv2.zip"
        echo "6ff031a26df7daebbfa3ccddc9af1450 awscliv2.zip" | md5sum -c
        if [ $? -ne 0 ]; then
            echo "MD5 checksum failed"
            exit 1
        fi
        unzip awscliv2.zip &> /dev/null
        ./aws/install

        # Clean up installation files
        rm -rf awscliv2.zip aws
    else
        echo "AWS CLI is already installed: $(which aws)"
    fi

    # Configure AWS CLI
    aws configure set aws_access_key_id "$DSTACK_AWS_ACCESS_KEY_ID"
    aws configure set aws_secret_access_key "$DSTACK_AWS_SECRET_ACCESS_KEY"
    aws configure set default.region $DSTACK_AWS_REGION
    echo "Logging in to AWS ECR..."
    aws ecr get-login-password --region $DSTACK_AWS_REGION | docker login --username AWS --password-stdin "$DSTACK_AWS_ECR_REGISTRY"
    if [ $? -eq 0 ]; then
        echo "AWS ECR login successful"
    else
        echo "AWS ECR login failed"
        exit 1
    fi
fi

# Run the cleanup process.
perform_cleanup

# Log the state of the disk AGAIN, after cleanup, to see what changed.
log_disk_state "AFTER CLEANUP"

echo "----------------------------------------------"
echo "Original Script execution completed"
echo "----------------------------------------------"
echo ""
echo "----------------------------------------------"
echo "Starting Custom Environment Variable Decryption (using Docker + Python)"
echo "----------------------------------------------"

# --- Custom Decryption Logic ---

# Configuration
APP_KEYS_FILE_ON_HOST="/tapp/appkeys.json" # Path on the CVM host OS
APP_KEYS_FILE_IN_CONTAINER="/tmp/appkeys.json" # Path inside the temporary container
ENCRYPTED_SUFFIX="_ENCRYPTED_ENV" # Suffix to identify encrypted variables
PYTHON_IMAGE="python:3.11-slim" # Or python:3.11-alpine if size is critical

# 1. Check prerequisites
echo "Checking prerequisites..."
if ! command -v docker &> /dev/null; then
    echo "Error: 'docker' command not found. Cannot perform decryption."
    exit 1
fi
if [ ! -f "$APP_KEYS_FILE_ON_HOST" ]; then
    echo "Error: App keys file not found at '$APP_KEYS_FILE_ON_HOST'."
    exit 1
fi

# Find environment variables ending with the specified suffix
# Find environment variables ending with the specified suffix using 'env' command
ENCRYPTED_VAR_NAMES=$(env | grep "${ENCRYPTED_SUFFIX}=" | cut -d= -f1)

if [ -z "$ENCRYPTED_VAR_NAMES" ]; then
    echo "Info: No environment variables ending in '$ENCRYPTED_SUFFIX' found. Skipping decryption."
    echo "----------------------------------------------"
    echo "Custom Decryption Skipped"
    echo "----------------------------------------------"
else
    # Preparing Python command, ensuring shim executable, the loop, etc.

echo "Found encrypted variables to process:"
echo "$ENCRYPTED_VAR_NAMES"
echo "---"

    # 2. Prepare the inline Python script for the container
PYTHON_DECRYPT_COMMAND=$(cat <<'EOF'
import sys, os, json, binascii
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.asymmetric import x25519

APP_KEYS_FILE = os.environ.get('APP_KEYS_FILE_IN_CONTAINER', '/tmp/appkeys.json')
ENCRYPTED_HEX = os.environ.get('ENCRYPTED_HEX_VALUE', '')

if not ENCRYPTED_HEX:
    print("Error: ENCRYPTED_HEX_VALUE env var not set inside container.", file=sys.stderr)
    sys.exit(1)

def read_priv_key(path):
    try:
        with open(path, 'r') as f: data = json.load(f)
        hex_key = data.get("env_crypt_key")
        if not hex_key: raise ValueError("env_crypt_key not found")
        return binascii.unhexlify(hex_key)
    except Exception as e: raise ValueError(f"Failed to read key from {path}: {e}")

def decrypt(encrypted_hex, priv_key_bytes):
    try:
        encrypted_data = binascii.unhexlify(encrypted_hex)
        if len(encrypted_data) < 44: raise ValueError("Encrypted data too short")
        eph_pub_bytes = encrypted_data[:32]
        iv = encrypted_data[32:44]
        ciphertext_tag = encrypted_data[44:] # Keep tag appended

        priv_key = x25519.X25519PrivateKey.from_private_bytes(priv_key_bytes)
        eph_pub_key = x25519.X25519PublicKey.from_public_bytes(eph_pub_bytes)
        shared = priv_key.exchange(eph_pub_key)

        aesgcm = AESGCM(shared)
        # Decrypt directly to bytes
        decrypted_bytes = aesgcm.decrypt(iv, ciphertext_tag, None)
        # Decode the bytes as UTF-8 string
        return decrypted_bytes.decode('utf-8')
    except Exception as e:
        # Provide more specific error context if possible
        raise RuntimeError(f"Decryption failed: {e}")

try:
    priv = read_priv_key(APP_KEYS_FILE)
    decrypted_string = decrypt(ENCRYPTED_HEX, priv)
    print(decrypted_string, end='') # Print the raw decrypted string to stdout
except Exception as e:
    print(f"Python Error: {e}", file=sys.stderr)
    sys.exit(1)
EOF
)

# Escape the python script properly for embedding within the sh -c '...' command
PYTHON_DECRYPT_COMMAND_ESCAPED=$(echo "$PYTHON_DECRYPT_COMMAND" | sed "s/'/'\\\\''/g")

# 3. Ensure Docker shim is executable BEFORE running the container
echo "Ensuring Docker shim is executable..."
if [ -f /usr/bin/containerd-shim-runc-v2 ]; then
    chmod +x /usr/bin/containerd-shim-runc-v2
else
    echo "Warning: Shim /usr/bin/containerd-shim-runc-v2 not found. Docker might fail."
fi

# Loop through each encrypted variable name
DECRYPTION_ERRORS=0
for encrypted_var_name in $ENCRYPTED_VAR_NAMES; do
    echo "--- Processing variable: $encrypted_var_name ---"

    # Get the encrypted value using indirect expansion
    encrypted_hex_value="${!encrypted_var_name}"

    if [ -z "$encrypted_hex_value" ]; then
        echo "Warning: Variable '$encrypted_var_name' is set but empty. Skipping."
        continue
    fi

    # Calculate the target decrypted variable name by removing the suffix
    decrypted_var_name="${encrypted_var_name%$ENCRYPTED_SUFFIX}"

    echo "Target decrypted variable name: $decrypted_var_name"

    # 4. Run the temporary Docker container to perform decryption for this variable
    echo "Running decryption container ($PYTHON_IMAGE) for $encrypted_var_name..."
    # Make sure pip install doesn't output progress to interfere with capturing the final print
    DECRYPTED_VALUE=$(docker run --rm \
        -e ENCRYPTED_HEX_VALUE="$encrypted_hex_value" \
        -e APP_KEYS_FILE_IN_CONTAINER="$APP_KEYS_FILE_IN_CONTAINER" \
        -v "$APP_KEYS_FILE_ON_HOST":"$APP_KEYS_FILE_IN_CONTAINER":ro \
        "$PYTHON_IMAGE" \
        sh -c "pip install cryptography --quiet --disable-pip-version-check --no-cache-dir > /dev/null && python -c '$PYTHON_DECRYPT_COMMAND_ESCAPED'"
    )
    DOCKER_EXIT_CODE=$?

    # 5. Check decryption result and export the decrypted variable
    if [ $DOCKER_EXIT_CODE -ne 0 ]; then
        echo "Error: Docker decryption container failed for '$encrypted_var_name' (exit code $DOCKER_EXIT_CODE)."
        DECRYPTION_ERRORS=$((DECRYPTION_ERRORS + 1))
        continue # Continue to the next variable
    fi

    # Check if the result is empty OR contains newline characters (which might indicate an error message)
    # We expect a single string value here.
    if [[ -z "$DECRYPTED_VALUE" ]] || [[ "$DECRYPTED_VALUE" == *$'\n'* ]]; then
        echo "Error: Decryption container returned an empty or multi-line value for '$encrypted_var_name'. Check container logs if possible."
        echo "Returned value was: '$DECRYPTED_VALUE'" # Show what was returned
        DECRYPTION_ERRORS=$((DECRYPTION_ERRORS + 1))
        continue # Continue to the next variable
    fi

    echo "Decryption successful for $encrypted_var_name."
    # Export the decrypted value under the new variable name
    export "$decrypted_var_name"="$DECRYPTED_VALUE"
    echo "Exported $decrypted_var_name for subsequent processes."
    # Debug only: print masked value for confirmation
    # echo "Decrypted value (masked): ${DECRYPTED_VALUE:0:3}..."

done # End of loop through encrypted variables

echo "---"

# Final status check
if [ $DECRYPTION_ERRORS -gt 0 ]; then
    echo "----------------------------------------------"
    echo "Custom Decryption Completed with $DECRYPTION_ERRORS ERRORS."
    echo "----------------------------------------------"
    exit 1 # Exit with error if any decryption failed
else
    echo "----------------------------------------------"
    echo "Custom Decryption Completed Successfully for all variables."
    echo "----------------------------------------------"
fi

fi # End of the main if/else block

# Script implicitly exits with 0 here if the 'else' block was skipped
# or if the 'else' block ran and DECRYPTION_ERRORS was 0.

# --- End of Custom Decryption Logic ---

# The Docker Compose command (e.g., docker compose up -d) would follow this script
# in the CVM's actual boot sequence, inheriting the exported variables.