# Magic WAN Configuration Generator

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A Cloudflare Worker that generates device configurations for Magic WAN IPsec and GRE tunnels. Supports both template-based and AI-powered configuration generation using Workers AI and Vectorize.

**Live URL:** https://mwan.cf-client-demo.com

## Features

### Template-Based Generation
Default mode using pre-defined templates for each device type. Produces consistent, well-tested configurations that follow Cloudflare's official documentation.

### AI-Powered Generation
Optional mode using Workers AI (Qwen 2.5 Coder 32B) with Vectorize for RAG-based generation. Queries embedded documentation to generate configurations dynamically. Includes automatic repetition detection to prevent looping output.

### Troubleshooting Chat
Interactive AI-powered troubleshooting assistant for diagnosing Magic WAN tunnel issues. Users can paste device logs, error messages, or describe problems to get context-aware diagnostics and fixes. The assistant understands:
- IKE Phase 1/2 failures (DH group mismatch, PSK issues, identity problems)
- Anti-replay errors (must be disabled for Magic WAN)
- NAT-T configuration issues (UDP 4500 encapsulation)
- MTU/fragmentation problems
- Device-specific debug commands

### NAT-T Support
Adds NAT Traversal configuration when the device is behind NAT/CGNAT. Configures UDP port 4500 encapsulation per device type.

### Scheduled Documentation Refresh
A daily cron job (midnight UTC) fetches the latest Cloudflare documentation pages, extracts configuration examples, generates embeddings, and updates the Vectorize index.

## Supported Devices

| Device | IPsec | GRE | Notes |
|--------|-------|-----|-------|
| Cisco IOS / IOS-XE | Yes | Yes | Full IKEv2 with tunnel protection |
| Cisco SD-WAN (Viptela) | Yes | Yes | Requires Cisco 8000v in router mode |
| Fortinet FortiGate | Yes | Yes | Phase1 interface name has 15-char limit |
| Palo Alto Networks | Yes | Yes | Set-based CLI configuration |
| Juniper SRX | Yes | Yes | Uses st0 secure tunnel interface |
| pfSense | Yes | No | GUI-based configuration guide |
| Ubiquiti / VyOS | Yes | Yes | VTI-based configuration |

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
| Anti-Replay | **Disabled** (required) | N/A |
| PFS | Group 20 | N/A |
| MTU | 1450 | 1476 |
| TCP MSS | 1350 | 1436 |

## Architecture

```
                                    +------------------+
                                    |   Cloudflare     |
                                    |   Magic WAN API  |
                                    +--------+---------+
                                             |
+------------------+     +-----------+       |
|   Web Browser    | --> |  Worker   | <-----+
+------------------+     +-----------+
                              |
          +-------------------+-------------------+
          |                   |                   |
    +-----+-----+       +-----+-----+       +-----+-----+
    | Template  |       |    AI     |       | Vectorize |
    | Generator |       | (Qwen 2.5)|       |  (RAG)    |
    +-----------+       +-----------+       +-----------+
```

## API Endpoints

### `GET /`
Returns the web interface.

### `POST /api/tunnels`
Fetches tunnel list from Cloudflare API.

```json
{
  "accountId": "your-account-id",
  "apiToken": "your-api-token"
}
```

### `POST /generate`
Generates device configuration using templates.

**Form data:**
- `deviceType`: cisco-ios, cisco-sdwan, fortinet, paloalto, juniper, pfsense, ubiquiti
- `tunnelType`: ipsec or gre
- `tunnelName`: Tunnel name
- `cloudflareEndpoint`: Cloudflare tunnel endpoint IP
- `customerEndpoint`: Customer WAN IP
- `interfaceAddress`: Tunnel interface address (CIDR)
- `tunnelFqdn`: Tunnel FQDN (IPsec only)
- `psk`: Pre-shared key (IPsec only)
- `accountId`: Cloudflare account ID
- `enableNatT`: Enable NAT-T (true/false)

### `POST /generate-ai`
Same as `/generate` but uses Workers AI with Vectorize context. Falls back to template generation if AI fails.

### `POST /troubleshoot`
AI-powered troubleshooting chat.

```json
{
  "message": "User's question or pasted logs",
  "context": {
    "deviceType": "cisco-ios",
    "tunnelType": "ipsec",
    "tunnelName": "tunnel-name",
    "cloudflareEndpoint": "162.x.x.x",
    "customerEndpoint": "203.x.x.x"
  },
  "history": []
}
```

### `POST /populate`
Populates Vectorize index with static documentation chunks.

### `POST /refresh-docs`
Fetches latest documentation from Cloudflare docs website and updates Vectorize. Also runs automatically daily via cron.

## Development

```bash
npm install
npm run dev
```

## Deployment

```bash
# Set your Cloudflare account ID
export CLOUDFLARE_ACCOUNT_ID="your-account-id"

npm run deploy
```

After deployment, populate the Vectorize index:

```bash
curl -X POST https://mwan.cf-client-demo.com/populate
```

## Configuration

Edit `wrangler.jsonc`:

```jsonc
{
  "name": "mwan-config-generator",
  "main": "src/index.ts",
  "compatibility_date": "2024-12-18",
  "routes": [
    {
      "pattern": "your-domain.com",
      "custom_domain": true
    }
  ],
  "triggers": {
    "crons": ["0 0 * * *"]
  },
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

## Requirements

- Cloudflare account with Magic WAN enabled
- API token with `Magic WAN Read` permission
- Workers AI binding
- Vectorize index (`mwan-docs`, 768 dimensions, cosine metric)

## Device-Specific Notes

### Fortinet FortiGate
- Phase1 interface name has a **15-character limit**
- `set asymroute-icmp enable` is required
- `set ike-port 4500` is only needed for NAT-T (and is a **global setting** affecting all tunnels)

### Cisco IOS/IOS-XE
- Use `crypto ikev2` (NOT `crypto isakmp` which is IKEv1)
- Add `crypto isakmp invalid-spi-recovery` for resilience

### Palo Alto Networks
- Anti-replay disabled via `set anti-replay no`
- Uses tunnel.1 interface

### Juniper SRX
- Uses st0.0 secure tunnel interface
- Version must be `v2-only`

### pfSense
- Configure via VPN > IPsec in the web interface
- Use **Routed (VTI)** mode for Phase 2
- **Replay Detection must be disabled** in Advanced Configuration
- Uses DH Group 14 (2048-bit) for compatibility
- Uses User FQDN for local identification
- GRE tunnels not supported in GUI (IPsec recommended)

### Ubiquiti / VyOS
- VTI-based configuration with IKEv2
- Uses DH Group 14 (2048-bit)
- For UniFi Cloud Gateway / Dream Machine, use the GUI instead of CLI

## Vectorize Index

The `mwan-docs` index stores embedded documentation:

- **Model**: bge-base-en-v1.5 (768 dimensions)
- **Metric**: Cosine similarity
- **Metadata**: deviceType, tunnelType, section, source, text

## References

- [Magic WAN Documentation](https://developers.cloudflare.com/magic-wan/)
- [IPsec Tunnels Reference](https://developers.cloudflare.com/magic-wan/reference/tunnels/)
- [Third-party Device Configuration](https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/)
- [Workers AI](https://developers.cloudflare.com/workers-ai/)
- [Vectorize](https://developers.cloudflare.com/vectorize/)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
