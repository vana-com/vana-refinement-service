#!/usr/bin/env python3
"""
Standalone script to fetch refiner-specific logs from remote Vana Refinement Service.

Usage:
    python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x... [options]

Requirements:
    pip install requests eth-account
"""

import argparse
import json
import os
import sys
from datetime import datetime
from typing import Optional, Dict, Any

try:
    import requests
    from eth_account import Account
    from eth_account.messages import encode_defunct
except ImportError as e:
    print(f"Error: Missing required dependency: {e}")
    print("Please install required packages: pip install requests eth-account")
    sys.exit(1)


class RefinerLogsFetcher:
    """Client for fetching refiner logs from remote Vana Refinement Service"""
    
    def __init__(self, base_url: str, private_key: str):
        self.base_url = base_url.rstrip('/')
        self.account = Account.from_key(private_key)
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'User-Agent': 'vana-refiner-logs-fetcher/1.0'
        })
    
    def _sign_message(self, message: str) -> str:
        """Sign a message with the admin wallet"""
        message_hash = encode_defunct(text=message)
        signature = self.account.sign_message(message_hash)
        return signature.signature.hex()
    
    def fetch_logs(self, 
                   refiner_id: int,
                   limit: Optional[int] = None,
                   start_date: Optional[str] = None,
                   end_date: Optional[str] = None,
                   job_id: Optional[str] = None,
                   timeout: int = 30) -> Dict[str, Any]:
        """
        Fetch logs for a specific refiner
        
        Args:
            refiner_id: The ID of the refiner
            limit: Maximum number of logs to return (default: 100, max: 1000)
            start_date: Start date filter (ISO format: 2024-01-01T00:00:00Z)
            end_date: End date filter (ISO format: 2024-01-31T23:59:59Z)
            job_id: Filter by specific job ID
            timeout: Request timeout in seconds
            
        Returns:
            Dict containing the API response
            
        Raises:
            requests.RequestException: For HTTP errors
            ValueError: For invalid parameters
        """
        # Sign the required message
        message_to_sign = f"admin_logs_refiner_{refiner_id}"
        signature = self._sign_message(message_to_sign)
        
        # Prepare request payload
        payload = {
            "signature": signature
        }
        
        if limit is not None:
            if limit <= 0 or limit > 1000:
                raise ValueError("Limit must be between 1 and 1000")
            payload["limit"] = limit
        
        if start_date:
            # Validate ISO format
            try:
                datetime.fromisoformat(start_date.replace('Z', '+00:00'))
                payload["start_date"] = start_date
            except ValueError:
                raise ValueError(f"Invalid start_date format: {start_date}. Use ISO format like '2024-01-01T00:00:00Z'")
        
        if end_date:
            try:
                datetime.fromisoformat(end_date.replace('Z', '+00:00'))
                payload["end_date"] = end_date
            except ValueError:
                raise ValueError(f"Invalid end_date format: {end_date}. Use ISO format like '2024-01-31T23:59:59Z'")
        
        if job_id:
            payload["job_id"] = job_id
        
        # Make the request
        url = f"{self.base_url}/logs/refiner/{refiner_id}"
        
        try:
            response = self.session.post(url, json=payload, timeout=timeout)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.Timeout:
            raise requests.RequestException(f"Request timed out after {timeout} seconds")
        except requests.exceptions.ConnectionError:
            raise requests.RequestException(f"Failed to connect to {url}")
        except requests.exceptions.HTTPError as e:
            if response.status_code == 403:
                raise requests.RequestException("Access denied: Invalid signature or not an admin wallet")
            elif response.status_code == 404:
                raise requests.RequestException(f"Refiner {refiner_id} not found or no logs available")
            else:
                try:
                    error_detail = response.json().get('detail', str(e))
                except:
                    error_detail = str(e)
                raise requests.RequestException(f"HTTP {response.status_code}: {error_detail}")


def format_log_entry(log: Dict[str, Any], show_full_logs: bool = False) -> str:
    """Format a single log entry for display"""
    timestamp = log.get('timestamp', 'N/A')
    job_id = log.get('job_id', 'N/A')
    level = log.get('level', 'INFO').upper()
    message = log.get('message', '')
    container = log.get('docker_container')
    exit_code = log.get('exit_code')
    full_logs = log.get('full_logs')
    
    # Format timestamp for readability
    try:
        dt = datetime.fromisoformat(timestamp.replace('Z', '+00:00'))
        formatted_time = dt.strftime('%Y-%m-%d %H:%M:%S UTC')
    except:
        formatted_time = timestamp
    
    lines = [
        f"[{formatted_time}] {level} - Job: {job_id}",
        f"  Message: {message}"
    ]
    
    if container:
        lines.append(f"  Container: {container}")
    
    if exit_code is not None:
        lines.append(f"  Exit Code: {exit_code}")
    
    if show_full_logs and full_logs:
        lines.append(f"  Full Logs:")
        # Indent each line of the full logs
        for line in full_logs.split('\n'):
            lines.append(f"    {line}")
    
    return '\n'.join(lines)


def main():
    parser = argparse.ArgumentParser(
        description='Fetch refiner-specific logs from Vana Refinement Service',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Basic usage
  python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x...

  # Fetch last 50 logs
  python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x... --limit 50

  # Fetch logs from date range
  python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x... \\
    --start-date 2024-01-01T00:00:00Z --end-date 2024-01-31T23:59:59Z

  # Fetch logs for specific job
  python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x... \\
    --job-id abc123def456

  # Show full Docker logs
  python fetch_refiner_logs.py --url https://refiner.example.com --refiner-id 123 --private-key 0x... \\
    --show-full-logs
        """
    )
    
    # Required arguments (can be provided via environment variables)
    parser.add_argument('--url', 
                       default=os.getenv('REFINER_URL'),
                       help='Base URL of the refinement service (e.g., https://refiner.example.com) [env: REFINER_URL]')
    parser.add_argument('--refiner-id', type=int, required=True,
                       help='ID of the refiner to fetch logs for')
    parser.add_argument('--private-key', 
                       default=os.getenv('ADMIN_PRIVATE_KEY'),
                       help='Private key of admin wallet (0x... format) [env: ADMIN_PRIVATE_KEY]')
    
    # Optional filtering arguments
    parser.add_argument('--limit', type=int, default=100,
                       help='Maximum number of logs to return (default: 100, max: 1000)')
    parser.add_argument('--start-date', 
                       help='Start date filter (ISO format: 2024-01-01T00:00:00Z)')
    parser.add_argument('--end-date',
                       help='End date filter (ISO format: 2024-01-31T23:59:59Z)')
    parser.add_argument('--job-id',
                       help='Filter logs by specific job ID')
    
    # Display options
    parser.add_argument('--show-full-logs', action='store_true',
                       help='Show full Docker logs in output (can be very verbose)')
    parser.add_argument('--json', action='store_true',
                       help='Output raw JSON response instead of formatted logs')
    parser.add_argument('--timeout', type=int, default=30,
                       help='Request timeout in seconds (default: 30)')
    
    args = parser.parse_args()
    
    # Validate required arguments
    if not args.url:
        parser.error("--url is required (or set REFINER_URL environment variable)")
    if not args.private_key:
        parser.error("--private-key is required (or set ADMIN_PRIVATE_KEY environment variable)")
    
    try:
        # Initialize the fetcher
        fetcher = RefinerLogsFetcher(args.url, args.private_key)
        
        print(f"Fetching logs for refiner {args.refiner_id} from {args.url}...")
        print(f"Admin wallet: {fetcher.account.address}")
        
        # Fetch the logs
        response = fetcher.fetch_logs(
            refiner_id=args.refiner_id,
            limit=args.limit,
            start_date=args.start_date,
            end_date=args.end_date,
            job_id=args.job_id,
            timeout=args.timeout
        )
        
        if args.json:
            # Output raw JSON
            print(json.dumps(response, indent=2))
        else:
            # Format and display logs
            refiner_id = response.get('refiner_id')
            total_entries = response.get('total_entries', 0)
            logs = response.get('logs', [])
            filters = response.get('filters_applied', {})
            
            print(f"\n{'='*60}")
            print(f"Refiner ID: {refiner_id}")
            print(f"Total Entries: {total_entries}")
            
            if filters:
                print("Filters Applied:")
                for key, value in filters.items():
                    if value is not None:
                        print(f"  {key}: {value}")
            
            print(f"{'='*60}")
            
            if logs:
                for i, log in enumerate(logs):
                    if i > 0:
                        print()  # Empty line between logs
                    print(format_log_entry(log, args.show_full_logs))
            else:
                print("No logs found matching the criteria.")
        
    except KeyboardInterrupt:
        print("\nOperation cancelled by user.")
        sys.exit(1)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)


if __name__ == '__main__':
    main() 