#!/usr/bin/env python3

import argparse
import re
import requests
import sys
import logging

def parse_arguments():
    parser = argparse.ArgumentParser(description="cloudflare ddns updater")
    parser.add_argument('--auth-email', required=True, help="login email")
    parser.add_argument('--auth-key', required=True, help="api token or global api key")
    parser.add_argument('--zone-identifier', required=True, help="can be found in overview section of domain")
    parser.add_argument('--record-name', required=True, help="which record to update")
    return parser.parse_args()

def get_public_ip():
    ip = requests.get('https://api.ipify.org').text
    ipv4_regex = r'^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$'

    if re.match(ipv4_regex, ip):
        return ip

    logging.error("failed to get a valid ipv4")
    sys.exit(2)

def update_dns(args, ip):
    headers = {
        'X-Auth-Email': args.auth_email,
        'Authorization': f'Bearer {args.auth_key}',
        'Content-Type': 'application/json'
    }

    # get old record
    res = requests.get(
        f'https://api.cloudflare.com/client/v4/zones/{args.zone_identifier}/dns_records',
        params={'type': 'A', 'name': args.record_name},
        headers=headers
    )

    res.raise_for_status()

    data = res.json()

    if data['result_info']['count'] == 0:
        logging.error(f" no existing record ({ip} for {args.record_name})")
        sys.exit(1)

    record = data['result'][0]
    old_ip = record['content']

    if ip == old_ip:
        logging.info(f"IP ({ip}) for {args.record_name} has not changed")
        return

    # new record
    update_data = {
        'type': 'A',
        'name': args.record_name,
        'content': ip,
        'ttl': 3600,
        'proxied': False
    }

    res = requests.patch(
        f'https://api.cloudflare.com/client/v4/zones/{args.zone_identifier}/dns_records/{record["id"]}',
        headers=headers,
        json=update_data
    )

    res.raise_for_status()

    if not res.json()['success']:
        logging.error(f"DDNS Updater: {ip} {args.record_name} DDNS update failed")
        sys.exit(1)

    logging.info(f"DDNS Updater: {ip} {args.record_name} DDNS updated")


def main():
    logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

    args = parse_arguments()
    ip = get_public_ip()
    update_dns(args, ip)

if __name__ == "__main__":
    main()
