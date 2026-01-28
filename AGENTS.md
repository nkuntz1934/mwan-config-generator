# AGENTS.md - AI Agent Guidelines for mwan-config-generator

## Project Overview

Cloudflare Worker that generates network device configurations for Magic WAN IPsec and GRE tunnels. Built with TypeScript, uses Workers AI and Vectorize for RAG-based generation.

**Stack**: Cloudflare Workers, TypeScript, Workers AI (Qwen 2.5 Coder), Vectorize (embeddings)

## Build & Development Commands

```bash
# Install dependencies
npm install

# Run local development server (uses wrangler)
npm run dev

# Deploy to Cloudflare
npm run deploy

# Populate Vectorize index after deployment
curl -X POST https://mwan.cf-client-demo.com/populate
```

### No Testing Framework

This project does not currently have a test suite. If adding tests:

- Consider using Vitest (recommended for Workers)
- Place tests in `__tests__/` or alongside source files as `*.test.ts`

### Linting & Formatting

ESLint and Prettier are configured. Run checks with:

```bash
npm run check         # Run all checks (lint + format + typecheck)
npm run lint          # ESLint only
npm run lint:fix      # ESLint with auto-fix
npm run format        # Prettier format all files
npm run format:check  # Prettier check only
npm run typecheck     # TypeScript type checking
```

## Project Structure

```
mwan-config-generator/
├── src/
│   └── index.ts          # Main Worker entry point (~2800 lines)
├── scripts/
│   └── populate-vectorize.ts  # Vectorize index population script
├── wrangler.jsonc        # Cloudflare Worker configuration
├── package.json
└── README.md
```

## Code Style Guidelines

### TypeScript Patterns

**Interfaces over Types**: Define interfaces for data structures at the top of the file.

```typescript
interface ConfigParams {
  deviceType: string;
  tunnelType: string;
  tunnelName: string;
  cloudflareEndpoint: string;
  customerEndpoint: string;
  interfaceAddress: string;
  tunnelFqdn: string;
  psk: string;
  accountId: string;
  enableNatT: boolean;
  stripComments: boolean;
}
```

**Env Interface**: Always define the Worker environment bindings.

```typescript
interface Env {
  AI: Ai;
  VECTORIZE: VectorizeIndex;
}
```

### Naming Conventions

| Element             | Convention           | Example                                |
| ------------------- | -------------------- | -------------------------------------- |
| Variables           | camelCase            | `tunnelName`, `customerIp`             |
| Functions           | camelCase            | `handleGenerate`, `getCustomerIp`      |
| Interfaces          | PascalCase           | `ConfigParams`, `TunnelInfo`           |
| Constants           | SCREAMING_SNAKE_CASE | `DOC_URLS`, `DOC_CHUNKS`               |
| Handler functions   | `handle` prefix      | `handleFetchTunnels`, `handlePopulate` |
| Generator functions | `generate` prefix    | `generateCiscoIos`, `generateFortinet` |
| Helper functions    | `get` prefix         | `getDeviceName`, `getCustomerIp`       |

### Formatting

- **Indentation**: 2 spaces
- **Quotes**: Double quotes for strings (especially in template literals)
- **Semicolons**: Required
- **Line length**: No strict limit, but keep readable
- **Trailing commas**: Use in multi-line arrays/objects

### Function Style

Use named function declarations for top-level functions:

```typescript
// Preferred
async function handleGenerate(request: Request): Promise<Response> {
  // ...
}

// Also acceptable for inline callbacks
const context = matches.matches.map((m) => {
  const text = m.metadata?.text || "";
  return `[${m.metadata?.section}]: ${text}`;
});
```

### Comments

Use section separators for major code blocks:

```typescript
// ============================================
// Cisco IOS/IOS-XE
// Reference: https://developers.cloudflare.com/magic-wan/...
// ============================================
function generateCiscoIos(p: ConfigParams): string {
```

Use `//` for inline comments, not `/* */`.

### Error Handling

Always wrap async operations in try/catch and return proper JSON error responses:

```typescript
try {
  const result = await someAsyncOperation();
  return new Response(JSON.stringify({ success: true, result }), {
    headers: { "Content-Type": "application/json" },
  });
} catch (error) {
  return new Response(JSON.stringify({ error: String(error) }), {
    status: 500,
    headers: { "Content-Type": "application/json" },
  });
}
```

### Response Patterns

Always set `Content-Type` header for JSON responses:

```typescript
return new Response(JSON.stringify({ config }), {
  headers: { "Content-Type": "application/json" },
});
```

For HTML responses:

```typescript
return new Response(getHtml(), {
  headers: { "Content-Type": "text/html" },
});
```

### Type Assertions

Use `as` for type assertions when parsing JSON:

```typescript
const body = (await request.json()) as { accountId: string; apiToken: string };
```

### Records for Mappings

Use `Record<string, T>` for dictionary-like objects:

```typescript
const DOC_URLS: Record<string, string> = {
  "cisco-ios": "https://...",
  fortinet: "https://...",
};

const generators: Record<string, (p: ConfigParams) => string> = {
  "cisco-ios": generateCiscoIos,
  fortinet: generateFortinet,
};
```

### Template Literals

Use template literals for multi-line config generation:

```typescript
return `! Cisco IOS Configuration
! Tunnel: ${p.tunnelName}

interface Tunnel1
 ip address ${customerIp} 255.255.255.254
 tunnel destination ${p.cloudflareEndpoint}
`;
```

## Worker-Specific Patterns

### Fetch Handler

The main Worker exports a `fetch` handler:

```typescript
export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/generate") {
      return handleGenerate(request);
    }

    return new Response(getHtml(), {
      headers: { "Content-Type": "text/html" },
    });
  },
};
```

### Scheduled Handler

For cron jobs:

```typescript
async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
  ctx.waitUntil(refreshDocsFromCloudflare(env));
},
```

### Workers AI Usage

```typescript
const embedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
  text: queryText,
});

const aiResponse = await env.AI.run("@cf/qwen/qwen2.5-coder-32b-instruct", {
  prompt,
  max_tokens: 2048,
  temperature: 0.1,
});
```

### Vectorize Usage

```typescript
// Query
const matches = await env.VECTORIZE.query(queryEmbedding.data[0], {
  topK: 8,
  filter: { deviceType: { $in: [params.deviceType, "all"] } },
  returnMetadata: "all",
});

// Upsert
await env.VECTORIZE.upsert(vectors);
```

## Important Domain Knowledge

### Supported Devices

- Cisco IOS/IOS-XE
- Cisco SD-WAN (Viptela)
- Fortinet FortiGate
- Palo Alto Networks
- Juniper SRX
- pfSense
- Ubiquiti/VyOS

### Critical Configuration Requirements

1. **Anti-replay MUST be disabled** - Cloudflare uses anycast
2. **IKEv2 only** - Never use IKEv1/ISAKMP
3. **IPsec MTU: 1450, MSS: 1350**
4. **GRE MTU: 1476, MSS: 1436**
5. **DH Group 20** (384-bit ECDH) is preferred

### Device-Specific Notes

- **FortiGate**: Phase1 interface name has 15-char limit; `ike-port 4500` is global
- **pfSense**: Uses GUI configuration; GRE not supported
- **Juniper SRX**: Uses st0 secure tunnel interface

## Adding New Features

### Adding a New Device Type

1. Add device URL to `DOC_URLS` constant
2. Add device name to `getDeviceName()` function
3. Create `generateDeviceName(p: ConfigParams): string` function
4. Add to `generators` Record in `generateConfig()`
5. Add documentation chunks to `getDocChunks()` for RAG
6. Update the HTML device select dropdown

### Adding a New API Endpoint

1. Add route check in main `fetch` handler
2. Create `handleEndpointName(request: Request, env: Env)` function
3. Parse request body/form data
4. Return JSON response with proper headers
