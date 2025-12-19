# Magic WAN Configuration Generator

A Cloudflare Worker that generates device configurations for Magic WAN IPsec and GRE tunnels.

## Overview

This tool connects to the Cloudflare API to fetch your Magic WAN tunnel details and generates copy-paste ready configurations for various network devices.

## Supported Devices

- Cisco IOS / IOS-XE
- Cisco SD-WAN (Viptela)
- Fortinet FortiGate
- Palo Alto Networks
- Juniper SRX
- Ubiquiti / VyOS

## Supported Tunnel Types

- IPsec (IKEv2)
- GRE

## Configuration Parameters

Generated configurations use Cloudflare's recommended settings:

| Parameter | IPsec Value | GRE Value |
|-----------|-------------|-----------|
| IKE Version | IKEv2 only | N/A |
| DH Group | 20 (384-bit ECDH) | N/A |
| Encryption | AES-256-CBC / AES-256-GCM | N/A |
| Integrity | SHA-256/384/512 | N/A |
| IKE Lifetime | 86400 seconds (24 hours) | N/A |
| IPsec Lifetime | 28800 seconds (8 hours) | N/A |
| Anti-Replay | Disabled | N/A |
| MTU | 1450 | 1476 |
| TCP MSS | 1350 | 1436 |

## Requirements

- Cloudflare account with Magic WAN enabled
- API token with `Magic Transit Read` permission
- Account ID

## Development

```bash
npm install
npm run dev
```

## Deployment

```bash
npm run deploy
```

## Configuration

Edit `wrangler.jsonc` to configure:

```json
{
  "name": "mwan-config-generator",
  "main": "src/index.ts",
  "compatibility_date": "2024-12-18",
  "account_id": "your-account-id",
  "routes": [
    {
      "pattern": "your-domain.com",
      "custom_domain": true
    }
  ]
}
```

## API Endpoints

### `GET /`
Returns the web interface.

### `POST /api/tunnels`
Fetches tunnel list from Cloudflare API.

Request body:
```json
{
  "accountId": "your-account-id",
  "apiToken": "your-api-token"
}
```

### `POST /generate`
Generates device configuration.

Form data:
- `deviceType`: Target device (cisco-ios, cisco-sdwan, fortinet, paloalto, juniper, ubiquiti)
- `tunnelType`: ipsec or gre
- `tunnelName`: Tunnel name
- `cloudflareEndpoint`: Cloudflare tunnel endpoint IP
- `customerEndpoint`: Customer tunnel endpoint IP
- `interfaceAddress`: Tunnel interface address
- `tunnelFqdn`: Tunnel FQDN (for IPsec IKE identity)
- `psk`: Pre-shared key (IPsec only)
- `accountId`: Cloudflare account ID

## References

- [Magic WAN Documentation](https://developers.cloudflare.com/magic-wan/)
- [IPsec Tunnels](https://developers.cloudflare.com/magic-wan/reference/tunnels/)
- [Third-party Device Configuration](https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/)
