# Magic WAN Configuration Generator

A Cloudflare Worker that generates device configurations for Magic WAN IPsec and GRE tunnels. Supports both template-based and AI-powered configuration generation using Workers AI and Vectorize.

## Overview

This tool connects to the Cloudflare API to fetch your Magic WAN tunnel details and generates copy-paste ready configurations for various network devices. The optional AI generation mode uses Workers AI with Vectorize to dynamically generate configurations based on current Cloudflare documentation.

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

## Features

### Template-Based Generation
Default mode using pre-defined templates for each device type. Produces consistent, well-tested configurations.

### AI-Powered Generation
Optional mode using Workers AI (Llama 3.1 70B) with Vectorize for RAG-based generation. Queries embedded documentation to generate configurations dynamically.

### NAT-T Support
Adds NAT Traversal configuration when the device is behind NAT/CGNAT. Configures UDP port 4500 encapsulation per device type.

## Requirements

- Cloudflare account with Magic WAN enabled
- API token with `Magic Transit Read` permission
- Account ID

For AI generation:
- Workers AI binding
- Vectorize index with embedded documentation

## Architecture

```
+------------------+     +------------------+     +------------------+
|   Web Interface  | --> |  Cloudflare API  | --> |  Tunnel Details  |
+------------------+     +------------------+     +------------------+
         |
         v
+------------------+     +------------------+
|  Template Gen    | OR  |   AI Generation  |
+------------------+     +------------------+
                               |
                               v
                    +------------------+
                    |    Vectorize     |
                    |   (Doc Chunks)   |
                    +------------------+
                               |
                               v
                    +------------------+
                    |   Workers AI     |
                    |  (Llama 3.1 70B) |
                    +------------------+
```

## Development

```bash
npm install
npm run dev
```

## Deployment

```bash
npm run deploy
```

### Populating Vectorize Index

After deployment, populate the Vectorize index with documentation:

```bash
curl -X POST https://your-worker.dev/populate
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
  ],
  "ai": {
    "binding": "AI"
  },
  "vectorize": [
    {
      "binding": "VECTORIZE",
      "index_name": "mwan-docs"
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
Generates device configuration using templates.

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
- `enableNatT`: Enable NAT-T (true/false)

### `POST /generate-ai`
Generates device configuration using Workers AI with Vectorize context.

Same form data as `/generate`. Falls back to template generation if AI fails.

Response includes:
- `config`: Generated configuration
- `aiGenerated`: Boolean indicating AI was used
- `fallback`: Boolean indicating fallback to template

### `POST /populate`
Populates Vectorize index with documentation chunks.

Response:
```json
{
  "success": true,
  "inserted": 10
}
```

## Vectorize Index

The `mwan-docs` index stores embedded documentation chunks for RAG-based generation:

- **Model**: bge-base-en-v1.5 (768 dimensions)
- **Metric**: cosine similarity
- **Metadata**: deviceType, tunnelType, section, source

Documentation chunks cover:
- Device-specific configuration syntax
- Cloudflare Magic WAN IPsec/GRE parameters
- NAT-T configuration per device
- Anti-replay requirements

## References

- [Magic WAN Documentation](https://developers.cloudflare.com/magic-wan/)
- [IPsec Tunnels](https://developers.cloudflare.com/magic-wan/reference/tunnels/)
- [Third-party Device Configuration](https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/)
- [Workers AI](https://developers.cloudflare.com/workers-ai/)
- [Vectorize](https://developers.cloudflare.com/vectorize/)
