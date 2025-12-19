interface Env {
  AI: Ai;
  VECTORIZE: VectorizeIndex;
}

// Cloudflare docs URLs for each device type
const DOC_URLS: Record<string, string> = {
  "cisco-ios": "https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/cisco-ios-xe/",
  "fortinet": "https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/fortinet/",
  "paloalto": "https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/palo-alto/",
  "juniper": "https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/juniper/",
  "cisco-sdwan": "https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/viptela/",
  "ipsec-params": "https://developers.cloudflare.com/magic-wan/reference/tunnels/",
};

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (request.method === "POST" && url.pathname === "/api/tunnels") {
      return handleFetchTunnels(request);
    }

    if (request.method === "POST" && url.pathname === "/generate") {
      return handleGenerate(request);
    }

    if (request.method === "POST" && url.pathname === "/generate-ai") {
      return handleGenerateAI(request, env);
    }

    if (request.method === "POST" && url.pathname === "/populate") {
      return handlePopulate(env);
    }

    if (request.method === "POST" && url.pathname === "/refresh-docs") {
      return handleRefreshDocs(env);
    }

    return new Response(getHtml(), {
      headers: { "Content-Type": "text/html" },
    });
  },

  // Scheduled handler - runs daily at midnight UTC
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    ctx.waitUntil(refreshDocsFromCloudflare(env));
  },
};

interface TunnelFromApi {
  id: string;
  name: string;
  cloudflare_endpoint: string;
  customer_endpoint: string;
  interface_address: string;
  description?: string;
}

interface TunnelInfo extends TunnelFromApi {
  fqdn: string;
  tunnelType: "ipsec" | "gre";
}

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
}

async function handleFetchTunnels(request: Request): Promise<Response> {
  const body = await request.json() as { accountId: string; apiToken: string };
  const { accountId, apiToken } = body;

  if (!accountId || !apiToken) {
    return new Response(JSON.stringify({ error: "Missing accountId or apiToken" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const headers = {
    Authorization: `Bearer ${apiToken}`,
    "Content-Type": "application/json",
  };

  try {
    // Fetch both IPsec and GRE tunnels in parallel
    const [ipsecRes, greRes] = await Promise.all([
      fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/magic/ipsec_tunnels`, { headers }),
      fetch(`https://api.cloudflare.com/client/v4/accounts/${accountId}/magic/gre_tunnels`, { headers }),
    ]);

    const [ipsecData, greData] = await Promise.all([
      ipsecRes.json() as Promise<{ success: boolean; result: { ipsec_tunnels: TunnelFromApi[] }; errors?: Array<{ message: string }> }>,
      greRes.json() as Promise<{ success: boolean; result: { gre_tunnels: TunnelFromApi[] }; errors?: Array<{ message: string }> }>,
    ]);

    // Check for auth errors (both will fail if token is bad)
    if (!ipsecData.success && !greData.success) {
      return new Response(JSON.stringify({ error: ipsecData.errors?.[0]?.message || "API error" }), {
        status: 400,
        headers: { "Content-Type": "application/json" },
      });
    }

    const tunnels: TunnelInfo[] = [];

    // Add IPsec tunnels
    if (ipsecData.success && ipsecData.result?.ipsec_tunnels) {
      for (const t of ipsecData.result.ipsec_tunnels) {
        tunnels.push({
          ...t,
          fqdn: `${t.id}.${accountId}.ipsec.cloudflare.com`,
          tunnelType: "ipsec",
        });
      }
    }

    // Add GRE tunnels
    if (greData.success && greData.result?.gre_tunnels) {
      for (const t of greData.result.gre_tunnels) {
        tunnels.push({
          ...t,
          fqdn: "",
          tunnelType: "gre",
        });
      }
    }

    return new Response(JSON.stringify({ tunnels, accountId }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: "Failed to fetch tunnels" }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

async function handleGenerate(request: Request): Promise<Response> {
  const formData = await request.formData();

  const params: ConfigParams = {
    deviceType: formData.get("deviceType") as string,
    tunnelType: formData.get("tunnelType") as string,
    tunnelName: formData.get("tunnelName") as string,
    cloudflareEndpoint: formData.get("cloudflareEndpoint") as string,
    customerEndpoint: formData.get("customerEndpoint") as string,
    interfaceAddress: formData.get("interfaceAddress") as string,
    tunnelFqdn: formData.get("tunnelFqdn") as string,
    psk: formData.get("psk") as string,
    accountId: formData.get("accountId") as string,
    enableNatT: formData.get("enableNatT") === "true",
  };

  const config = generateConfig(params);

  return new Response(JSON.stringify({ config }), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleGenerateAI(request: Request, env: Env): Promise<Response> {
  const formData = await request.formData();

  const params: ConfigParams = {
    deviceType: formData.get("deviceType") as string,
    tunnelType: formData.get("tunnelType") as string,
    tunnelName: formData.get("tunnelName") as string,
    cloudflareEndpoint: formData.get("cloudflareEndpoint") as string,
    customerEndpoint: formData.get("customerEndpoint") as string,
    interfaceAddress: formData.get("interfaceAddress") as string,
    tunnelFqdn: formData.get("tunnelFqdn") as string,
    psk: formData.get("psk") as string,
    accountId: formData.get("accountId") as string,
    enableNatT: formData.get("enableNatT") === "true",
  };

  try {
    // Generate embedding for the query
    const queryText = `${getDeviceName(params.deviceType)} ${params.tunnelType} configuration for Magic WAN tunnel ${params.enableNatT ? "with NAT-T enabled" : ""}`;

    const queryEmbedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
      text: queryText,
    });

    if (!queryEmbedding.data || !queryEmbedding.data[0]) {
      throw new Error("Failed to generate query embedding");
    }

    // Query Vectorize for relevant documentation
    const matches = await env.VECTORIZE.query(queryEmbedding.data[0], {
      topK: 8,
      filter: {
        deviceType: { $in: [params.deviceType, "all"] },
        tunnelType: { $in: [params.tunnelType, "all"] },
      },
      returnMetadata: "all",
    });

    // Build context from matched documents
    const context = matches.matches
      .map((m) => {
        const text = m.metadata?.text || "";
        return `[${m.metadata?.section}]: ${text}`;
      })
      .join("\n\n");

    // Calculate customer IP from interface address
    const customerIp = getCustomerIp(params.interfaceAddress);

    // Generate config using AI
    const prompt = `You are generating device configurations for Cloudflare Magic WAN.

CRITICAL RULES - FOLLOW EXACTLY:
1. Use ONLY the configuration syntax from the REFERENCE DOCUMENTATION below
2. Do NOT use IKEv1 (crypto isakmp) - ONLY use IKEv2 (crypto ikev2)
3. Do NOT invent or hallucinate any commands not shown in the documentation
4. Copy the exact command structure from the documentation, substituting only the values

TUNNEL PARAMETERS:
- Tunnel Name: ${params.tunnelName}
- Cloudflare Endpoint: ${params.cloudflareEndpoint}
- Customer WAN IP: ${params.customerEndpoint || "YOUR_WAN_IP"}
- Customer Tunnel IP: ${customerIp}
${params.tunnelType === "ipsec" ? `- Pre-Shared Key: ${params.psk}
- Account FQDN: ${params.accountId}.ipsec.cloudflare.com
- NAT-T Enabled: ${params.enableNatT}` : ""}

REFERENCE DOCUMENTATION (USE THIS EXACTLY):
${context}

OUTPUT REQUIREMENTS:
- Generate ONLY device commands with comments (! or #)
- No markdown, no explanations, no notes
- Substitute the TUNNEL PARAMETERS into the REFERENCE DOCUMENTATION config
${params.tunnelType === "ipsec" ? "- Anti-replay MUST be disabled (set security-association replay disable)" : "- MTU 1476, MSS 1436 for GRE"}
${params.enableNatT ? "- Include NAT-T config (nat force-encap or equivalent)" : ""}

Generate the ${getDeviceName(params.deviceType)} configuration:`;

    // Use Qwen 2.5 Coder - optimized for code/config generation
    const aiResponse = await env.AI.run("@cf/qwen/qwen2.5-coder-32b-instruct", {
      prompt,
      max_tokens: 2048,
      temperature: 0.1,
    });

    const config = typeof aiResponse === "string"
      ? aiResponse
      : (aiResponse as { response?: string }).response || "";

    return new Response(JSON.stringify({ config, aiGenerated: true }), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    // Fallback to template-based generation
    const config = generateConfig(params);
    return new Response(JSON.stringify({ config, aiGenerated: false, fallback: true }), {
      headers: { "Content-Type": "application/json" },
    });
  }
}

async function handlePopulate(env: Env): Promise<Response> {
  const DOC_CHUNKS = getDocChunks();
  const vectors: VectorizeVector[] = [];

  for (const chunk of DOC_CHUNKS) {
    const embedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
      text: chunk.text,
    });

    if (embedding.data && embedding.data[0]) {
      vectors.push({
        id: chunk.id,
        values: embedding.data[0],
        metadata: { ...chunk.metadata, text: chunk.text },
      });
    }
  }

  // Upsert in batches
  const batchSize = 50;
  let inserted = 0;

  for (let i = 0; i < vectors.length; i += batchSize) {
    const batch = vectors.slice(i, i + batchSize);
    await env.VECTORIZE.upsert(batch);
    inserted += batch.length;
  }

  return new Response(JSON.stringify({ success: true, inserted }), {
    headers: { "Content-Type": "application/json" },
  });
}

async function handleRefreshDocs(env: Env): Promise<Response> {
  try {
    const result = await refreshDocsFromCloudflare(env);
    return new Response(JSON.stringify(result), {
      headers: { "Content-Type": "application/json" },
    });
  } catch (error) {
    return new Response(JSON.stringify({ error: String(error) }), {
      status: 500,
      headers: { "Content-Type": "application/json" },
    });
  }
}

async function refreshDocsFromCloudflare(env: Env): Promise<{ success: boolean; updated: number; sources: string[] }> {
  const vectors: VectorizeVector[] = [];
  const sources: string[] = [];

  for (const [deviceType, url] of Object.entries(DOC_URLS)) {
    try {
      // Fetch the documentation page
      const response = await fetch(url, {
        headers: {
          "User-Agent": "Cloudflare-Worker-MWAN-Config-Generator/1.0",
          "Accept": "text/html",
        },
      });

      if (!response.ok) {
        console.error(`Failed to fetch ${url}: ${response.status}`);
        continue;
      }

      const html = await response.text();

      // Extract code blocks and relevant content from HTML
      const docContent = extractDocContent(html, deviceType);

      if (!docContent) {
        console.error(`No content extracted from ${url}`);
        continue;
      }

      // Generate embedding
      const embedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
        text: docContent,
      });

      if (embedding.data && embedding.data[0]) {
        const tunnelType = deviceType === "ipsec-params" ? "ipsec" : "ipsec";
        // Truncate text to fit Vectorize 10KB metadata limit
        const truncatedText = docContent.length > 8000 ? docContent.substring(0, 8000) + "\n[TRUNCATED]" : docContent;
        vectors.push({
          id: `live-${deviceType}-config`,
          values: embedding.data[0],
          metadata: {
            deviceType: deviceType === "ipsec-params" ? "all" : deviceType,
            tunnelType,
            section: "live-docs",
            source: url,
            text: truncatedText,
            updatedAt: new Date().toISOString(),
          },
        });
        sources.push(url);
      }
    } catch (error) {
      console.error(`Error processing ${url}:`, error);
    }
  }

  // Upsert vectors
  if (vectors.length > 0) {
    await env.VECTORIZE.upsert(vectors);
  }

  return { success: true, updated: vectors.length, sources };
}

function extractDocContent(html: string, deviceType: string): string | null {
  // Extract code blocks (between <pre> or ```...```)
  const codeBlocks: string[] = [];

  // Match <pre><code>...</code></pre> blocks
  const preCodeRegex = /<pre[^>]*><code[^>]*>([\s\S]*?)<\/code><\/pre>/gi;
  let match;
  while ((match = preCodeRegex.exec(html)) !== null) {
    const code = match[1]
      .replace(/<[^>]+>/g, "") // Remove HTML tags
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
    if (code.length > 50) {
      codeBlocks.push(code);
    }
  }

  // Also match standalone <pre> blocks
  const preRegex = /<pre[^>]*>([\s\S]*?)<\/pre>/gi;
  while ((match = preRegex.exec(html)) !== null) {
    const code = match[1]
      .replace(/<[^>]+>/g, "")
      .replace(/&lt;/g, "<")
      .replace(/&gt;/g, ">")
      .replace(/&amp;/g, "&")
      .replace(/&quot;/g, '"')
      .replace(/&#39;/g, "'")
      .trim();
    if (code.length > 50 && !codeBlocks.includes(code)) {
      codeBlocks.push(code);
    }
  }

  if (codeBlocks.length === 0) {
    return null;
  }

  // Build context with device type prefix
  const deviceNames: Record<string, string> = {
    "cisco-ios": "Cisco IOS-XE",
    "fortinet": "Fortinet FortiGate",
    "paloalto": "Palo Alto Networks",
    "juniper": "Juniper SRX",
    "cisco-sdwan": "Cisco SD-WAN Viptela",
    "ipsec-params": "Magic WAN IPsec Parameters",
  };

  const prefix = `${deviceNames[deviceType] || deviceType} configuration for Cloudflare Magic WAN. MUST use IKEv2 (NOT IKEv1/ISAKMP). Anti-replay MUST be disabled.\n\nEXACT CONFIGURATION FROM CLOUDFLARE DOCS:\n`;

  return prefix + codeBlocks.join("\n\n---\n\n");
}

function getDeviceName(deviceType: string): string {
  const names: Record<string, string> = {
    "cisco-ios": "Cisco IOS/IOS-XE",
    "cisco-sdwan": "Cisco SD-WAN (Viptela)",
    "fortinet": "Fortinet FortiGate",
    "paloalto": "Palo Alto Networks",
    "juniper": "Juniper SRX",
    "ubiquiti": "Ubiquiti/VyOS",
  };
  return names[deviceType] || deviceType;
}

interface DocChunk {
  id: string;
  text: string;
  metadata: {
    deviceType: string;
    tunnelType: string;
    section: string;
    source: string;
  };
}

function getDocChunks(): DocChunk[] {
  return [
    {
      id: "cisco-ios-ipsec-full-config",
      text: `Cisco IOS-XE IPsec Configuration for Magic WAN. MUST use IKEv2 (crypto ikev2), NOT IKEv1/ISAKMP.
EXACT CONFIG:
crypto ikev2 proposal CF_PROPOSAL
 encryption aes-cbc-256
 integrity sha512 sha384 sha256
 group 20
crypto ikev2 policy CF_POLICY
 match fvrf any
 proposal CF_PROPOSAL
crypto ikev2 keyring CF_KEYRING
 peer CLOUDFLARE
  address <cloudflare_endpoint>
  pre-shared-key <psk>
crypto ikev2 profile CF_PROFILE
 match identity remote address <cloudflare_endpoint> 255.255.255.255
 identity local fqdn <account_id>.ipsec.cloudflare.com
 authentication remote pre-share
 authentication local pre-share
 keyring local CF_KEYRING
 lifetime 86400
 dpd 10 3 periodic
 no config-exchange request
crypto ipsec profile CF_IPSEC_PROFILE
 set security-association lifetime kilobytes disable
 set security-association replay disable
 set pfs group20
 set ikev2-profile CF_PROFILE
interface Tunnel1
 ip address <customer_ip> 255.255.255.254
 ip mtu 1450
 ip tcp adjust-mss 1350
 tunnel source <customer_wan_ip>
 tunnel mode ipsec ipv4
 tunnel destination <cloudflare_endpoint>
 tunnel path-mtu-discovery
 tunnel protection ipsec profile CF_IPSEC_PROFILE
For NAT-T add: nat force-encap under crypto ikev2 profile`,
      metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "full-config", source: "developers.cloudflare.com" }
    },
    {
      id: "fortinet-ipsec-overview",
      text: "Fortinet FortiGate IPsec Configuration for Magic WAN. CRITICAL: Must enable asymmetric routing (set asymroute-icmp enable) and set IKE port to 4500 (set ike-port 4500). Use IKEv2 with AES-256-GCM and DH group 20. Phase 1 keylife: 86400 seconds. Phase 2 must disable replay. For NAT-T, set nattraversal enable in phase1-interface.",
      metadata: { deviceType: "fortinet", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
    },
    {
      id: "paloalto-ipsec-overview",
      text: "Palo Alto Networks IPsec Configuration for Magic WAN. Use IKEv2 with DH group 20 and AES-256-CBC encryption. IKE lifetime: 24 hours. IPsec lifetime: 8 hours. Anti-replay must be disabled (set anti-replay no). For NAT-T, configure nat-traversal enable on the IKE gateway.",
      metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
    },
    {
      id: "juniper-ipsec-overview",
      text: "Juniper SRX IPsec Configuration for Magic WAN. Use IKEv2 only (version v2-only). DH group 20 with AES-256-CBC. IKE lifetime: 86400 seconds. IPsec lifetime: 28800 seconds. Anti-replay must be disabled (no-anti-replay). For NAT-T, set nat-keepalive 10 on the IKE gateway.",
      metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
    },
    {
      id: "cisco-sdwan-ipsec-overview",
      text: "Cisco SD-WAN (Viptela) IPsec Configuration for Magic WAN. IPsec is only supported on Cisco 8000v in router mode. Use IKEv2 with cipher-suite aes256-cbc-sha256 and group 20. IKE rekey 86400, IPsec rekey 28800. Replay window must be 0 (disabled). For NAT-T, add 'nat-t enable' in the IKE section.",
      metadata: { deviceType: "cisco-sdwan", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
    },
    {
      id: "ubiquiti-ipsec-overview",
      text: "Ubiquiti EdgeRouter / VyOS IPsec Configuration for Magic WAN. Use IKEv2 with AES-256 and SHA-256. DH group 20. IKE lifetime: 86400 seconds. ESP lifetime: 28800 seconds. For NAT-T, use force-udp-encapsulation on the site-to-site peer.",
      metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
    },
    {
      id: "mwan-ipsec-params",
      text: "Magic WAN IPsec Parameters: IKE Version IKEv2 only, DH Group 20 (384-bit ECDH), Encryption AES-256-CBC or AES-256-GCM, Integrity SHA-256/384/512, IKE Lifetime 86400 seconds, IPsec Lifetime 28800 seconds, Anti-Replay MUST be disabled, PFS Group 20, MTU 1450, TCP MSS 1350.",
      metadata: { deviceType: "all", tunnelType: "ipsec", section: "parameters", source: "developers.cloudflare.com" }
    },
    {
      id: "mwan-gre-params",
      text: "Magic WAN GRE Parameters: MTU 1476, TCP MSS 1436, Keepalive 10 seconds with 3 retries recommended.",
      metadata: { deviceType: "all", tunnelType: "gre", section: "parameters", source: "developers.cloudflare.com" }
    },
    {
      id: "mwan-anti-replay",
      text: "Magic WAN Anti-Replay: MUST be disabled on customer device. Cloudflare uses anycast, packets may arrive at different data centers. Cisco IOS: set security-association replay disable. Fortinet: set replay disable. Palo Alto: set anti-replay no. Juniper: set no-anti-replay. Viptela: replay-window 0.",
      metadata: { deviceType: "all", tunnelType: "ipsec", section: "anti-replay", source: "developers.cloudflare.com" }
    },
  ];
}

function generateConfig(p: ConfigParams): string {
  const generators: Record<string, (p: ConfigParams) => string> = {
    "cisco-ios": generateCiscoIos,
    "cisco-sdwan": generateCiscoSdwan,
    "fortinet": generateFortinet,
    "paloalto": generatePaloAlto,
    "juniper": generateJuniper,
    "ubiquiti": generateUbiquiti,
  };

  const generator = generators[p.deviceType];
  if (!generator) {
    return "// Unsupported device type";
  }

  return generator(p);
}

// Helper to get customer side IP from Cloudflare's interface address
function getCustomerIp(cfInterfaceAddr: string): string {
  const ip = cfInterfaceAddr.split("/")[0];
  const parts = ip.split(".");
  // Customer IP is typically +1 from Cloudflare's IP in a /31
  parts[3] = (parseInt(parts[3]) + 1).toString();
  return parts.join(".");
}

// ============================================
// Cisco IOS/IOS-XE
// Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/cisco-ios-xe/
// ============================================
function generateCiscoIos(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);
  const accountFqdn = p.accountId ? `${p.accountId}.ipsec.cloudflare.com` : "";

  if (p.tunnelType === "gre") {
    return `! Cisco IOS/IOS-XE GRE Configuration for Cloudflare Magic WAN
! Tunnel: ${p.tunnelName}
! Cloudflare Endpoint: ${p.cloudflareEndpoint}
! Reference: https://developers.cloudflare.com/magic-wan/reference/gre-ipsec-tunnels/

interface Tunnel1
 description Cloudflare Magic WAN - ${p.tunnelName}
 ip address ${customerIp} 255.255.255.254
 tunnel source ${p.customerEndpoint || "<YOUR_WAN_IP>"}
 tunnel destination ${p.cloudflareEndpoint}
 tunnel mode gre ip
 ip mtu 1476
 ip tcp adjust-mss 1436
 keepalive 10 3
 no shutdown
`;
  }

  return `! Cisco IOS/IOS-XE IPsec Configuration for Cloudflare Magic WAN
! Tunnel: ${p.tunnelName}
! Cloudflare Endpoint: ${p.cloudflareEndpoint}
! FQDN: ${p.tunnelFqdn}
! Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/cisco-ios-xe/

! ============================================
! IKEv2 Proposal - DH Group 20, AES-256, SHA256
! ============================================
crypto ikev2 proposal CF-MWAN-PROPOSAL
 encryption aes-cbc-256
 integrity sha512 sha384 sha256
 group 20 14

crypto ikev2 policy CF-MWAN-POLICY
 proposal CF-MWAN-PROPOSAL

crypto ikev2 keyring CF-MWAN-KEYRING
 peer CLOUDFLARE
  address ${p.cloudflareEndpoint}
  pre-shared-key ${p.psk}

crypto ikev2 profile CF-MWAN-PROFILE
 match identity remote address ${p.cloudflareEndpoint} 255.255.255.255
 identity local fqdn ${accountFqdn}
 authentication remote pre-share
 authentication local pre-share
 keyring local CF-MWAN-KEYRING
 lifetime 86400
 dpd 10 3 periodic${p.enableNatT ? "\n nat force-encap" : ""}

! ============================================
! IPsec Transform Set
! ============================================
crypto ipsec transform-set CF-MWAN-TRANSFORM esp-aes 256 esp-sha256-hmac
 mode tunnel

crypto ipsec profile CF-MWAN-IPSEC-PROFILE
 set transform-set CF-MWAN-TRANSFORM
 set ikev2-profile CF-MWAN-PROFILE
 set security-association lifetime kilobytes disable
 set security-association replay disable
 set pfs group20

! ============================================
! Tunnel Interface - MTU 1450, MSS 1350
! ============================================
interface Tunnel1
 description Cloudflare Magic WAN - ${p.tunnelName} (${p.tunnelFqdn})
 ip address ${customerIp} 255.255.255.254
 tunnel source ${p.customerEndpoint || "<YOUR_WAN_IP>"}
 tunnel mode ipsec ipv4
 tunnel destination ${p.cloudflareEndpoint}
 tunnel protection ipsec profile CF-MWAN-IPSEC-PROFILE
 tunnel path-mtu-discovery
 ip mtu 1450
 ip tcp adjust-mss 1350
 no shutdown

! Enable IKE invalid SPI recovery
crypto isakmp invalid-spi-recovery
`;
}

// ============================================
// Cisco SD-WAN (Viptela)
// Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/viptela/
// ============================================
function generateCiscoSdwan(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);

  if (p.tunnelType === "gre") {
    return `! Cisco SD-WAN GRE Configuration for Cloudflare Magic WAN
! Tunnel: ${p.tunnelName}
! Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/viptela/

vpn 0
 interface gre1
  description "Cloudflare Magic WAN - ${p.tunnelName}"
  ip address ${customerIp}/31
  tunnel-source-interface ge0/0
  tunnel-destination ${p.cloudflareEndpoint}
  mtu 1476
  tcp-mss-adjust 1436
  no shutdown
`;
  }

  return `! Cisco SD-WAN IPsec Configuration for Cloudflare Magic WAN
! Tunnel: ${p.tunnelName}
! Note: IPsec only supported on Cisco 8000v in router mode
! FQDN: ${p.tunnelFqdn}
! Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/viptela/

vpn 0
 interface ipsec1
  description "Cloudflare Magic WAN - ${p.tunnelName}"
  ip address ${customerIp}/31
  tunnel-source-interface ge0/0
  tunnel-destination ${p.cloudflareEndpoint}
  ike
   version 2
   rekey 86400
   cipher-suite aes256-cbc-sha256
   group 20${p.enableNatT ? "\n   nat-t enable" : ""}
   authentication-type
    pre-shared-key
     pre-shared-secret ${p.psk}
  ipsec
   rekey 28800
   replay-window 0
   cipher-suite aes256-cbc-sha256
   perfect-forward-secrecy group-20
  mtu 1450
  tcp-mss-adjust 1350
  no shutdown
`;
}

// ============================================
// Fortinet FortiGate
// Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/fortinet/
// ============================================
function generateFortinet(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);
  const accountFqdn = p.accountId ? `${p.accountId}.ipsec.cloudflare.com` : "";

  if (p.tunnelType === "gre") {
    return `# FortiGate GRE Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}

config system gre-tunnel
    edit "CF-MWAN-${p.tunnelName}"
        set interface "wan1"
        set remote-gw ${p.cloudflareEndpoint}
        set local-gw ${p.customerEndpoint || "<YOUR_WAN_IP>"}
    next
end

config system interface
    edit "CF-MWAN-${p.tunnelName}"
        set ip ${customerIp} 255.255.255.254
        set allowaccess ping
        set mtu-override enable
        set mtu 1476
    next
end
`;
  }

  return `# FortiGate IPsec Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}
# FQDN: ${p.tunnelFqdn}
# Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/fortinet/

# ============================================
# REQUIRED Global Settings
# ============================================
config system settings
    set asymroute-icmp enable
end

config system global
    set ike-port 4500
end

# ============================================
# Phase 1 - AES-GCM-256, DH Group 20
# ============================================
config vpn ipsec phase1-interface
    edit "CF-MWAN-${p.tunnelName}"
        set interface "wan1"
        set ike-version 2
        set peertype any
        set net-device enable
        set proposal aes256gcm-prfsha512 aes256gcm-prfsha384 aes256gcm-prfsha256
        set dhgrp 20
        set remote-gw ${p.cloudflareEndpoint}
        set psksecret ${p.psk}
        set keylife 86400${p.enableNatT ? "\n        set nattraversal enable" : ""}
${accountFqdn ? `        set localid "${accountFqdn}"` : ""}
    next
end

# ============================================
# Phase 2 - Replay MUST be disabled
# ============================================
config vpn ipsec phase2-interface
    edit "CF-MWAN-${p.tunnelName}-P2"
        set phase1name "CF-MWAN-${p.tunnelName}"
        set proposal aes256gcm
        set dhgrp 20
        set replay disable
        set keepalive enable
        set auto-negotiate enable
    next
end

# ============================================
# Tunnel Interface
# ============================================
config system interface
    edit "CF-MWAN-${p.tunnelName}"
        set ip ${customerIp} 255.255.255.255
        set remote-ip ${p.cloudflareEndpoint} 255.255.255.254
        set allowaccess ping
    next
end
`;
}

// ============================================
// Palo Alto Networks
// Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/palo-alto/
// ============================================
function generatePaloAlto(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);
  const accountFqdn = p.accountId ? `${p.accountId}.ipsec.cloudflare.com` : "";

  if (p.tunnelType === "gre") {
    return `# Palo Alto GRE Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}
# Note: Native GRE varies by PAN-OS version

set network interface tunnel units tunnel.1 ip ${customerIp}/31
set network interface tunnel units tunnel.1 mtu 1476

set zone Cloudflare network layer3 tunnel.1
`;
  }

  return `# Palo Alto IPsec Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}
# FQDN: ${p.tunnelFqdn}
# Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/palo-alto/

# ============================================
# IKE Crypto Profile - DH Group 20, AES-256-CBC
# ============================================
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto hash sha512 sha384 sha256
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto dh-group group20
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto encryption aes-256-cbc
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto lifetime hours 24

# ============================================
# IPsec Crypto Profile
# ============================================
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto esp authentication sha256 sha1
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto esp encryption aes-256-cbc
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto dh-group group20
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto lifetime hours 8

# ============================================
# IKE Gateway
# ============================================
set network ike gateway CF_MWAN_GW authentication pre-shared-key key ${p.psk}
set network ike gateway CF_MWAN_GW protocol ikev2 dpd enable yes
set network ike gateway CF_MWAN_GW protocol ikev2 ike-crypto-profile CF_IKE_Crypto
set network ike gateway CF_MWAN_GW protocol version ikev2${p.enableNatT ? "\nset network ike gateway CF_MWAN_GW protocol ikev2 nat-traversal enable" : ""}
set network ike gateway CF_MWAN_GW local-address interface ethernet1/1
set network ike gateway CF_MWAN_GW local-address ip ${p.customerEndpoint || "<YOUR_WAN_IP>"}
set network ike gateway CF_MWAN_GW peer-address ip ${p.cloudflareEndpoint}
${accountFqdn ? `set network ike gateway CF_MWAN_GW local-id type fqdn id ${accountFqdn}` : ""}

# ============================================
# Tunnel Interface - MTU 1450, Allow Ping
# ============================================
set network interface tunnel units tunnel.1 ip ${customerIp}/31
set network interface tunnel units tunnel.1 mtu 1450
set network interface tunnel units tunnel.1 comment "Cloudflare Magic WAN - ${p.tunnelName}"

set network profiles interface-management-profile Allow_Ping ping yes
set network interface tunnel units tunnel.1 interface-management-profile Allow_Ping

# ============================================
# IPsec Tunnel - Disable anti-replay
# ============================================
set network tunnel ipsec CF_MWAN_IPsec auto-key ike-gateway CF_MWAN_GW
set network tunnel ipsec CF_MWAN_IPsec auto-key ipsec-crypto-profile CF_IPsec_Crypto
set network tunnel ipsec CF_MWAN_IPsec tunnel-interface tunnel.1
set network tunnel ipsec CF_MWAN_IPsec anti-replay no

# ============================================
# Zone
# ============================================
set zone Cloudflare network layer3 tunnel.1
`;
}

// ============================================
// Juniper SRX
// Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/juniper/
// ============================================
function generateJuniper(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);
  const accountFqdn = p.accountId ? `${p.accountId}.ipsec.cloudflare.com` : "";

  if (p.tunnelType === "gre") {
    return `# Juniper SRX GRE Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}

set interfaces gr-0/0/0 unit 0 description "Cloudflare Magic WAN - ${p.tunnelName}"
set interfaces gr-0/0/0 unit 0 tunnel source ${p.customerEndpoint || "<YOUR_WAN_IP>"}
set interfaces gr-0/0/0 unit 0 tunnel destination ${p.cloudflareEndpoint}
set interfaces gr-0/0/0 unit 0 family inet address ${customerIp}/31
set interfaces gr-0/0/0 unit 0 family inet mtu 1476

set security zones security-zone cloudflare interfaces gr-0/0/0.0 host-inbound-traffic system-services all
set security zones security-zone cloudflare interfaces gr-0/0/0.0 host-inbound-traffic protocols all
`;
  }

  return `# Juniper SRX IPsec Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}
# FQDN: ${p.tunnelFqdn}
# Reference: https://developers.cloudflare.com/magic-wan/configuration/manually/third-party/juniper/

# ============================================
# IKE Proposal - DH Group 20, AES-256-CBC
# ============================================
set security ike proposal cf_ike_prop authentication-method pre-shared-keys
set security ike proposal cf_ike_prop dh-group group20
set security ike proposal cf_ike_prop authentication-algorithm sha-256
set security ike proposal cf_ike_prop encryption-algorithm aes-256-cbc
set security ike proposal cf_ike_prop lifetime-seconds 86400

set security ike policy cf_ike_pol mode main
set security ike policy cf_ike_pol proposals cf_ike_prop
set security ike policy cf_ike_pol pre-shared-key ascii-text "${p.psk}"

# ============================================
# IKE Gateway
# ============================================
set security ike gateway cf_gw ike-policy cf_ike_pol
set security ike gateway cf_gw address ${p.cloudflareEndpoint}
set security ike gateway cf_gw external-interface ge-0/0/0.0
set security ike gateway cf_gw local-address ${p.customerEndpoint || "<YOUR_WAN_IP>"}
set security ike gateway cf_gw version v2-only${p.enableNatT ? "\nset security ike gateway cf_gw nat-keepalive 10" : ""}
${accountFqdn ? `set security ike gateway cf_gw local-identity fqdn ${accountFqdn}` : ""}

# ============================================
# IPsec Proposal
# ============================================
set security ipsec proposal cf_ipsec_prop protocol esp
set security ipsec proposal cf_ipsec_prop authentication-algorithm hmac-sha-256-128
set security ipsec proposal cf_ipsec_prop encryption-algorithm aes-256-cbc
set security ipsec proposal cf_ipsec_prop lifetime-seconds 28800

set security ipsec policy cf_ipsec_pol perfect-forward-secrecy keys group20
set security ipsec policy cf_ipsec_pol proposals cf_ipsec_prop

# ============================================
# IPsec VPN - Disable anti-replay
# ============================================
set security ipsec vpn cf_vpn bind-interface st0.0
set security ipsec vpn cf_vpn ike gateway cf_gw
set security ipsec vpn cf_vpn ike no-anti-replay
set security ipsec vpn cf_vpn ike ipsec-policy cf_ipsec_pol
set security ipsec vpn cf_vpn establish-tunnels immediately

# ============================================
# Tunnel Interface
# ============================================
set interfaces st0 unit 0 description "Cloudflare Magic WAN - ${p.tunnelName}"
set interfaces st0 unit 0 family inet address ${customerIp}/31

# ============================================
# Security Zone
# ============================================
set security zones security-zone cloudflare interfaces st0.0 host-inbound-traffic system-services all
set security zones security-zone cloudflare interfaces st0.0 host-inbound-traffic protocols all
`;
}

// ============================================
// Ubiquiti EdgeRouter / VyOS
// ============================================
function generateUbiquiti(p: ConfigParams): string {
  const customerIp = getCustomerIp(p.interfaceAddress);

  if (p.tunnelType === "gre") {
    return `# Ubiquiti/VyOS GRE Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}

set interfaces tunnel tun0 description "Cloudflare Magic WAN - ${p.tunnelName}"
set interfaces tunnel tun0 encapsulation gre
set interfaces tunnel tun0 local-ip ${p.customerEndpoint || "<YOUR_WAN_IP>"}
set interfaces tunnel tun0 remote-ip ${p.cloudflareEndpoint}
set interfaces tunnel tun0 address ${customerIp}/31
set interfaces tunnel tun0 mtu 1476

# commit ; save
`;
  }

  return `# Ubiquiti/VyOS IPsec Configuration for Cloudflare Magic WAN
# Tunnel: ${p.tunnelName}
# FQDN: ${p.tunnelFqdn}

# ============================================
# IKE Group - DH Group 20, AES-256, SHA-256
# ============================================
set vpn ipsec ike-group CF-IKE proposal 1 encryption aes256
set vpn ipsec ike-group CF-IKE proposal 1 hash sha256
set vpn ipsec ike-group CF-IKE proposal 1 dh-group 20
set vpn ipsec ike-group CF-IKE lifetime 86400
set vpn ipsec ike-group CF-IKE key-exchange ikev2
set vpn ipsec ike-group CF-IKE dead-peer-detection action restart
set vpn ipsec ike-group CF-IKE dead-peer-detection interval 30
set vpn ipsec ike-group CF-IKE dead-peer-detection timeout 120

# ============================================
# ESP Group
# ============================================
set vpn ipsec esp-group CF-ESP proposal 1 encryption aes256
set vpn ipsec esp-group CF-ESP proposal 1 hash sha256
set vpn ipsec esp-group CF-ESP lifetime 28800
set vpn ipsec esp-group CF-ESP pfs dh-group20
set vpn ipsec esp-group CF-ESP mode tunnel

# ============================================
# Site-to-Site Peer
# ============================================
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} description "Cloudflare Magic WAN - ${p.tunnelName}"
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} authentication mode pre-shared-secret
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} authentication pre-shared-secret "${p.psk}"
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} ike-group CF-IKE
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} local-address ${p.customerEndpoint || "<YOUR_WAN_IP>"}
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} vti bind vti0
set vpn ipsec site-to-site peer ${p.cloudflareEndpoint} vti esp-group CF-ESP${p.enableNatT ? `\nset vpn ipsec site-to-site peer ${p.cloudflareEndpoint} force-udp-encapsulation` : ""}

set vpn ipsec ipsec-interfaces interface eth0

# ============================================
# VTI Interface - MTU 1450
# ============================================
set interfaces vti vti0 description "Cloudflare Magic WAN - ${p.tunnelName}"
set interfaces vti vti0 address ${customerIp}/31
set interfaces vti vti0 mtu 1450

# commit ; save
`;
}

// ============================================
// HTML - Sophisticated Enterprise UI
// ============================================
function getHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Magic WAN Configuration Generator</title>
  <link rel="icon" type="image/svg+xml" href="data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'%3E%3Cdefs%3E%3ClinearGradient id='g' x1='0%25' y1='0%25' x2='100%25' y2='100%25'%3E%3Cstop offset='0%25' stop-color='%23f6821f'/%3E%3Cstop offset='100%25' stop-color='%23ff9d4d'/%3E%3C/linearGradient%3E%3C/defs%3E%3Crect width='32' height='32' rx='6' fill='url(%23g)'/%3E%3Cpath d='M22 13c-.4-2-2-3.5-4-3.5-1.8 0-3.3 1.2-3.8 2.8H13.5c-1.8 0-3.2 1.4-3.2 3.2s1.4 3.2 3.2 3.2h8.8c1.5 0 2.8-1.3 2.8-2.8s-1.1-2.7-2.4-2.9z' fill='white'/%3E%3C/svg%3E">
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&family=JetBrains+Mono:wght@400;500&display=swap" rel="stylesheet">
  <style>
    :root {
      --cf-orange: #f6821f;
      --cf-orange-dark: #e5701a;
      --cf-orange-light: #ff9d4d;
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-tertiary: #21262d;
      --bg-elevated: #1c2128;
      --border-default: #30363d;
      --border-muted: #21262d;
      --text-primary: #f0f6fc;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --success: #238636;
      --success-emphasis: #2ea043;
      --error: #da3633;
      --shadow-lg: 0 16px 48px rgba(0,0,0,.35);
      --shadow-md: 0 8px 24px rgba(0,0,0,.25);
      --radius-sm: 6px;
      --radius-md: 8px;
      --radius-lg: 12px;
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
      background: var(--bg-primary);
      min-height: 100vh;
      color: var(--text-primary);
      line-height: 1.5;
    }

    /* Header */
    .header {
      background: var(--bg-secondary);
      border-bottom: 1px solid var(--border-default);
      padding: 1rem 2rem;
      position: sticky;
      top: 0;
      z-index: 100;
      backdrop-filter: blur(12px);
    }

    .header-content {
      max-width: 1200px;
      margin: 0 auto;
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .logo {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .logo-icon {
      width: 32px;
      height: 32px;
      background: linear-gradient(135deg, var(--cf-orange) 0%, var(--cf-orange-light) 100%);
      border-radius: var(--radius-sm);
      display: flex;
      align-items: center;
      justify-content: center;
    }

    .logo-icon svg { width: 20px; height: 20px; fill: white; }

    .logo-text {
      font-weight: 600;
      font-size: 1.125rem;
      letter-spacing: -0.02em;
    }

    .logo-text span { color: var(--cf-orange); }

    .status-badge {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      padding: 0.375rem 0.75rem;
      background: var(--bg-tertiary);
      border: 1px solid var(--border-default);
      border-radius: 100px;
      font-size: 0.75rem;
      color: var(--text-secondary);
    }

    .status-dot {
      width: 8px;
      height: 8px;
      border-radius: 50%;
      background: var(--text-muted);
    }

    .status-dot.connected { background: var(--success-emphasis); }

    /* Main Layout */
    .main {
      max-width: 1200px;
      margin: 0 auto;
      padding: 2rem;
      display: grid;
      grid-template-columns: 380px 1fr;
      gap: 2rem;
      min-height: calc(100vh - 65px);
    }

    @media (max-width: 1024px) {
      .main {
        grid-template-columns: 1fr;
        max-width: 600px;
      }
    }

    /* Sidebar */
    .sidebar {
      display: flex;
      flex-direction: column;
      gap: 1.5rem;
    }

    /* Cards */
    .card {
      background: var(--bg-secondary);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      overflow: hidden;
    }

    .card-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-default);
      display: flex;
      align-items: center;
      justify-content: space-between;
    }

    .card-title {
      font-size: 0.875rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .card-title-icon {
      width: 18px;
      height: 18px;
      color: var(--text-secondary);
    }

    .card-body { padding: 1.25rem; }

    .card-footer {
      padding: 1rem 1.25rem;
      background: var(--bg-tertiary);
      border-top: 1px solid var(--border-default);
    }

    /* Step Indicator */
    .step-indicator {
      display: flex;
      align-items: center;
      gap: 0.5rem;
      font-size: 0.75rem;
      color: var(--text-muted);
    }

    .step-num {
      width: 20px;
      height: 20px;
      border-radius: 50%;
      background: var(--bg-tertiary);
      border: 1px solid var(--border-default);
      display: flex;
      align-items: center;
      justify-content: center;
      font-weight: 500;
      font-size: 0.7rem;
    }

    .step-num.active {
      background: var(--cf-orange);
      border-color: var(--cf-orange);
      color: white;
    }

    .step-num.done {
      background: var(--success);
      border-color: var(--success);
      color: white;
    }

    /* Form Elements */
    .form-group { margin-bottom: 1rem; }
    .form-group:last-child { margin-bottom: 0; }

    .form-label {
      display: block;
      font-size: 0.8125rem;
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 0.5rem;
    }

    .form-input {
      width: 100%;
      padding: 0.625rem 0.875rem;
      background: var(--bg-primary);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      color: var(--text-primary);
      font-size: 0.875rem;
      font-family: inherit;
      transition: border-color 0.15s, box-shadow 0.15s;
    }

    .form-input:focus {
      outline: none;
      border-color: var(--cf-orange);
      box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.15);
    }

    .form-input::placeholder { color: var(--text-muted); }

    .form-input:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    select.form-input {
      cursor: pointer;
      appearance: none;
      background-image: url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' width='16' height='16' fill='%238b949e' viewBox='0 0 16 16'%3E%3Cpath d='M4.427 6.427l3.396 3.396a.25.25 0 00.354 0l3.396-3.396A.25.25 0 0011.396 6H4.604a.25.25 0 00-.177.427z'/%3E%3C/svg%3E");
      background-repeat: no-repeat;
      background-position: right 0.75rem center;
      padding-right: 2.5rem;
    }

    select.form-input option {
      background: var(--bg-secondary);
      color: var(--text-primary);
    }

    .form-row {
      display: grid;
      grid-template-columns: 1fr 1fr;
      gap: 1rem;
    }

    /* Buttons */
    .btn {
      display: inline-flex;
      align-items: center;
      justify-content: center;
      gap: 0.5rem;
      padding: 0.625rem 1rem;
      border: 1px solid transparent;
      border-radius: var(--radius-md);
      font-family: inherit;
      font-size: 0.875rem;
      font-weight: 500;
      cursor: pointer;
      transition: all 0.15s;
      width: 100%;
    }

    .btn-primary {
      background: var(--cf-orange);
      color: white;
    }

    .btn-primary:hover:not(:disabled) {
      background: var(--cf-orange-dark);
    }

    .btn-primary:disabled {
      opacity: 0.5;
      cursor: not-allowed;
    }

    .btn-secondary {
      background: var(--bg-tertiary);
      border-color: var(--border-default);
      color: var(--text-primary);
    }

    .btn-secondary:hover:not(:disabled) {
      background: var(--bg-elevated);
      border-color: var(--text-muted);
    }

    .btn-ghost {
      background: transparent;
      color: var(--text-secondary);
      padding: 0.5rem;
      width: auto;
    }

    .btn-ghost:hover { color: var(--text-primary); }

    .btn-icon { width: 16px; height: 16px; }

    /* Spinner */
    .spinner {
      width: 16px;
      height: 16px;
      border: 2px solid rgba(255,255,255,0.3);
      border-top-color: white;
      border-radius: 50%;
      animation: spin 0.8s linear infinite;
    }

    @keyframes spin { to { transform: rotate(360deg); } }

    /* Tunnel Selector */
    .tunnel-option {
      display: flex;
      align-items: center;
      gap: 0.75rem;
    }

    .tunnel-badge {
      display: inline-flex;
      align-items: center;
      padding: 0.125rem 0.5rem;
      border-radius: 100px;
      font-size: 0.625rem;
      font-weight: 600;
      text-transform: uppercase;
      letter-spacing: 0.05em;
    }

    .tunnel-badge.ipsec {
      background: rgba(246, 130, 31, 0.15);
      color: var(--cf-orange);
    }

    .tunnel-badge.gre {
      background: rgba(139, 148, 158, 0.15);
      color: var(--text-secondary);
    }

    /* Tunnel Info Panel */
    .tunnel-info {
      margin-top: 0.75rem;
      padding: 0.875rem;
      background: var(--bg-tertiary);
      border-radius: var(--radius-md);
      font-size: 0.8125rem;
      display: none;
    }

    .tunnel-info.visible { display: block; }

    .tunnel-info-grid {
      display: grid;
      gap: 0.5rem;
    }

    .tunnel-info-row {
      display: flex;
      justify-content: space-between;
      align-items: center;
    }

    .tunnel-info-label { color: var(--text-muted); }

    .tunnel-info-value {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.75rem;
      color: var(--text-secondary);
    }

    /* PSK Field */
    .psk-field {
      display: none;
    }

    .psk-field.visible { display: block; }

    /* NAT-T Field */
    .nat-t-field {
      display: none;
    }

    .nat-t-field.visible { display: block; }

    .checkbox-label {
      display: flex;
      align-items: center;
      gap: 0.625rem;
      cursor: pointer;
      user-select: none;
    }

    .checkbox-input {
      position: absolute;
      opacity: 0;
      width: 0;
      height: 0;
    }

    .checkbox-box {
      width: 18px;
      height: 18px;
      border: 1px solid var(--border-default);
      border-radius: 4px;
      background: var(--bg-primary);
      display: flex;
      align-items: center;
      justify-content: center;
      transition: all 0.15s;
      flex-shrink: 0;
    }

    .checkbox-box::after {
      content: '';
      width: 10px;
      height: 10px;
      background: var(--cf-orange);
      border-radius: 2px;
      opacity: 0;
      transform: scale(0);
      transition: all 0.15s;
    }

    .checkbox-input:checked + .checkbox-box {
      border-color: var(--cf-orange);
    }

    .checkbox-input:checked + .checkbox-box::after {
      opacity: 1;
      transform: scale(1);
    }

    .checkbox-input:focus + .checkbox-box {
      box-shadow: 0 0 0 3px rgba(246, 130, 31, 0.15);
    }

    .checkbox-text {
      font-size: 0.875rem;
      font-weight: 500;
      color: var(--text-primary);
    }

    .checkbox-hint {
      font-size: 0.75rem;
      color: var(--text-muted);
      margin-top: 0.375rem;
      padding-left: 1.625rem;
    }

    /* Output Panel */
    .output-panel {
      background: var(--bg-secondary);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-lg);
      display: flex;
      flex-direction: column;
      min-height: 400px;
    }

    .output-header {
      padding: 1rem 1.25rem;
      border-bottom: 1px solid var(--border-default);
      display: flex;
      align-items: center;
      justify-content: space-between;
      flex-shrink: 0;
    }

    .output-title {
      font-size: 0.875rem;
      font-weight: 600;
      display: flex;
      align-items: center;
      gap: 0.5rem;
    }

    .output-meta {
      display: flex;
      align-items: center;
      gap: 1rem;
    }

    .output-device {
      font-size: 0.75rem;
      color: var(--text-muted);
      padding: 0.25rem 0.625rem;
      background: var(--bg-tertiary);
      border-radius: var(--radius-sm);
    }

    .output-body {
      flex: 1;
      overflow: auto;
      padding: 1.25rem;
    }

    .output-placeholder {
      height: 100%;
      display: flex;
      flex-direction: column;
      align-items: center;
      justify-content: center;
      color: var(--text-muted);
      text-align: center;
      padding: 2rem;
    }

    .output-placeholder-icon {
      width: 48px;
      height: 48px;
      color: var(--border-default);
      margin-bottom: 1rem;
    }

    .output-placeholder-title {
      font-weight: 500;
      color: var(--text-secondary);
      margin-bottom: 0.25rem;
    }

    .output-placeholder-text {
      font-size: 0.875rem;
    }

    .code-block {
      font-family: 'JetBrains Mono', monospace;
      font-size: 0.8125rem;
      line-height: 1.6;
      white-space: pre;
      color: var(--text-secondary);
      display: none;
    }

    .code-block.visible { display: block; }

    /* Toast */
    .toast-container {
      position: fixed;
      bottom: 1.5rem;
      right: 1.5rem;
      z-index: 1000;
    }

    .toast {
      padding: 0.75rem 1rem;
      background: var(--bg-elevated);
      border: 1px solid var(--border-default);
      border-radius: var(--radius-md);
      box-shadow: var(--shadow-lg);
      display: flex;
      align-items: center;
      gap: 0.625rem;
      font-size: 0.875rem;
      transform: translateY(100px);
      opacity: 0;
      transition: all 0.3s cubic-bezier(0.16, 1, 0.3, 1);
    }

    .toast.show {
      transform: translateY(0);
      opacity: 1;
    }

    .toast-icon {
      width: 18px;
      height: 18px;
      flex-shrink: 0;
    }

    .toast.success .toast-icon { color: var(--success-emphasis); }
    .toast.error .toast-icon { color: var(--error); }

    /* Section divider */
    .divider {
      height: 1px;
      background: var(--border-default);
      margin: 1rem 0;
    }

    /* Collapsed state */
    .card.collapsed .card-body { display: none; }
    .card.collapsed .card-footer { display: none; }

    /* Connected state */
    .card.connected { border-color: var(--success); }
    .card.connected .card-header { background: rgba(35, 134, 54, 0.1); }

    /* Animations */
    .fade-in {
      animation: fadeIn 0.3s ease;
    }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(8px); }
      to { opacity: 1; transform: translateY(0); }
    }

    /* Empty state */
    .empty-state {
      text-align: center;
      padding: 2rem;
      color: var(--text-muted);
    }

    .empty-state-icon {
      width: 40px;
      height: 40px;
      margin: 0 auto 1rem;
      color: var(--border-default);
    }
  </style>
</head>
<body>
  <header class="header">
    <div class="header-content">
      <div class="logo">
        <div class="logo-icon">
          <svg viewBox="0 0 24 24" fill="currentColor"><path d="M16.5 9c-.5-2.5-2.5-4.5-5-4.5-2.2 0-4.1 1.5-4.7 3.5H6c-2.2 0-4 1.8-4 4s1.8 4 4 4h11c1.9 0 3.5-1.6 3.5-3.5S18.4 9 16.5 9z"/></svg>
        </div>
        <div class="logo-text">Magic WAN <span>Config Generator</span></div>
      </div>
      <div class="status-badge">
        <div class="status-dot" id="statusDot"></div>
        <span id="statusText">Not connected</span>
      </div>
    </div>
  </header>

  <main class="main">
    <aside class="sidebar">
      <!-- Step 1: Connect -->
      <div class="card" id="connectCard">
        <div class="card-header">
          <div class="card-title">
            <svg class="card-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="3" y="11" width="18" height="11" rx="2" ry="2"/><path d="M7 11V7a5 5 0 0 1 10 0v4"/></svg>
            Connect to Cloudflare
          </div>
          <div class="step-indicator">
            <div class="step-num active" id="step1Num">1</div>
          </div>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Account ID</label>
            <input type="text" class="form-input" id="accountId" placeholder="Enter your account ID">
          </div>
          <div class="form-group">
            <label class="form-label">API Token</label>
            <input type="password" class="form-input" id="apiToken" placeholder="API token with Magic WAN read access">
          </div>
        </div>
        <div class="card-footer">
          <button class="btn btn-primary" id="connectBtn" onclick="connect()">
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg>
            Connect
          </button>
        </div>
      </div>

      <!-- Step 2: Configure -->
      <div class="card" id="configCard" style="opacity: 0.5; pointer-events: none;">
        <div class="card-header">
          <div class="card-title">
            <svg class="card-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.65 1.65 0 0 0 .33 1.82l.06.06a2 2 0 0 1 0 2.83 2 2 0 0 1-2.83 0l-.06-.06a1.65 1.65 0 0 0-1.82-.33 1.65 1.65 0 0 0-1 1.51V21a2 2 0 0 1-2 2 2 2 0 0 1-2-2v-.09A1.65 1.65 0 0 0 9 19.4a1.65 1.65 0 0 0-1.82.33l-.06.06a2 2 0 0 1-2.83 0 2 2 0 0 1 0-2.83l.06-.06a1.65 1.65 0 0 0 .33-1.82 1.65 1.65 0 0 0-1.51-1H3a2 2 0 0 1-2-2 2 2 0 0 1 2-2h.09A1.65 1.65 0 0 0 4.6 9a1.65 1.65 0 0 0-.33-1.82l-.06-.06a2 2 0 0 1 0-2.83 2 2 0 0 1 2.83 0l.06.06a1.65 1.65 0 0 0 1.82.33H9a1.65 1.65 0 0 0 1-1.51V3a2 2 0 0 1 2-2 2 2 0 0 1 2 2v.09a1.65 1.65 0 0 0 1 1.51 1.65 1.65 0 0 0 1.82-.33l.06-.06a2 2 0 0 1 2.83 0 2 2 0 0 1 0 2.83l-.06.06a1.65 1.65 0 0 0-.33 1.82V9a1.65 1.65 0 0 0 1.51 1H21a2 2 0 0 1 2 2 2 2 0 0 1-2 2h-.09a1.65 1.65 0 0 0-1.51 1z"/></svg>
            Configure
          </div>
          <div class="step-indicator">
            <div class="step-num" id="step2Num">2</div>
          </div>
        </div>
        <div class="card-body">
          <div class="form-group">
            <label class="form-label">Select Tunnel</label>
            <select class="form-input" id="tunnelSelect" onchange="onTunnelSelect()">
              <option value="">Choose a tunnel...</option>
            </select>
            <div class="tunnel-info" id="tunnelInfo">
              <div class="tunnel-info-grid">
                <div class="tunnel-info-row">
                  <span class="tunnel-info-label">Type</span>
                  <span class="tunnel-info-value" id="infoType">-</span>
                </div>
                <div class="tunnel-info-row">
                  <span class="tunnel-info-label">Cloudflare Endpoint</span>
                  <span class="tunnel-info-value" id="infoCfEndpoint">-</span>
                </div>
                <div class="tunnel-info-row">
                  <span class="tunnel-info-label">Customer Endpoint</span>
                  <span class="tunnel-info-value" id="infoCustEndpoint">-</span>
                </div>
                <div class="tunnel-info-row">
                  <span class="tunnel-info-label">Interface Address</span>
                  <span class="tunnel-info-value" id="infoInterface">-</span>
                </div>
              </div>
            </div>
          </div>

          <div class="form-group psk-field" id="pskField">
            <label class="form-label">Pre-Shared Key (PSK)</label>
            <input type="password" class="form-input" id="psk" placeholder="Enter tunnel PSK">
          </div>

          <div class="form-group nat-t-field" id="natTField">
            <label class="checkbox-label">
              <input type="checkbox" id="enableNatT" class="checkbox-input">
              <span class="checkbox-box"></span>
              <span class="checkbox-text">Enable NAT-T</span>
            </label>
            <div class="checkbox-hint">Enable if device is behind NAT/CGNAT (uses UDP port 4500)</div>
          </div>

          <div class="divider"></div>

          <div class="form-group">
            <label class="form-label">Target Device</label>
            <select class="form-input" id="deviceType">
              <option value="cisco-ios">Cisco IOS / IOS-XE</option>
              <option value="cisco-sdwan">Cisco SD-WAN (Viptela)</option>
              <option value="fortinet">Fortinet FortiGate</option>
              <option value="paloalto">Palo Alto Networks</option>
              <option value="juniper">Juniper SRX</option>
              <option value="ubiquiti">Ubiquiti / VyOS</option>
            </select>
          </div>

          <div class="form-group">
            <label class="checkbox-label">
              <input type="checkbox" id="useAI" class="checkbox-input">
              <span class="checkbox-box"></span>
              <span class="checkbox-text">Use AI Generation</span>
            </label>
            <div class="checkbox-hint">Generate config using Workers AI with current documentation context</div>
          </div>
        </div>
        <div class="card-footer">
          <button class="btn btn-primary" id="generateBtn" onclick="generateConfig()" disabled>
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
            Generate Configuration
          </button>
        </div>
      </div>

      <!-- Disconnect -->
      <button class="btn btn-ghost" id="disconnectBtn" onclick="disconnect()" style="display: none;">
        <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><polyline points="16 17 21 12 16 7"/><line x1="21" y1="12" x2="9" y2="12"/></svg>
        Disconnect &amp; Start Over
      </button>
    </aside>

    <!-- Output Panel -->
    <div class="output-panel">
      <div class="output-header">
        <div class="output-title">
          <svg class="card-title-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="4 17 10 11 4 5"/><line x1="12" y1="19" x2="20" y2="19"/></svg>
          Configuration Output
        </div>
        <div class="output-meta">
          <span class="output-device" id="outputDevice" style="display: none;">-</span>
          <button class="btn btn-secondary" id="copyBtn" onclick="copyConfig()" style="display: none; width: auto;">
            <svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/></svg>
            Copy
          </button>
        </div>
      </div>
      <div class="output-body">
        <div class="output-placeholder" id="outputPlaceholder">
          <svg class="output-placeholder-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg>
          <div class="output-placeholder-title">No configuration generated</div>
          <div class="output-placeholder-text">Connect and select a tunnel to generate device configuration</div>
        </div>
        <pre class="code-block" id="codeBlock"></pre>
      </div>
    </div>
  </main>

  <div class="toast-container">
    <div class="toast" id="toast">
      <svg class="toast-icon" id="toastIcon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"></svg>
      <span id="toastMessage"></span>
    </div>
  </div>

  <script>
    let tunnelsData = [];
    let selectedTunnel = null;
    let accountId = '';

    async function connect() {
      accountId = document.getElementById('accountId').value.trim();
      const apiToken = document.getElementById('apiToken').value.trim();

      if (!accountId || !apiToken) {
        showToast('Please enter both Account ID and API Token', 'error');
        return;
      }

      const btn = document.getElementById('connectBtn');
      btn.innerHTML = '<div class="spinner"></div> Connecting...';
      btn.disabled = true;

      try {
        const res = await fetch('/api/tunnels', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ accountId, apiToken })
        });
        const data = await res.json();

        if (data.error) {
          showToast(data.error, 'error');
          btn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Connect';
          btn.disabled = false;
          return;
        }

        tunnelsData = data.tunnels;

        if (tunnelsData.length === 0) {
          showToast('No tunnels found in this account', 'error');
          btn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Connect';
          btn.disabled = false;
          return;
        }

        // Update tunnel dropdown
        const select = document.getElementById('tunnelSelect');
        select.innerHTML = '<option value="">Choose a tunnel...</option>' +
          tunnelsData.map((t, i) =>
            '<option value="' + i + '">' + t.name + ' [' + t.tunnelType.toUpperCase() + ']</option>'
          ).join('');

        // Update UI state
        document.getElementById('statusDot').classList.add('connected');
        document.getElementById('statusText').textContent = 'Connected';

        document.getElementById('connectCard').classList.add('connected', 'collapsed');
        document.getElementById('step1Num').classList.remove('active');
        document.getElementById('step1Num').classList.add('done');
        document.getElementById('step1Num').innerHTML = '<svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3"><polyline points="20 6 9 17 4 12"/></svg>';

        const configCard = document.getElementById('configCard');
        configCard.style.opacity = '1';
        configCard.style.pointerEvents = 'auto';
        configCard.classList.add('fade-in');
        document.getElementById('step2Num').classList.add('active');

        document.getElementById('disconnectBtn').style.display = 'flex';

        showToast('Connected! Found ' + tunnelsData.length + ' tunnel' + (tunnelsData.length > 1 ? 's' : ''), 'success');

      } catch (e) {
        showToast('Failed to connect', 'error');
        btn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Connect';
        btn.disabled = false;
      }
    }

    function onTunnelSelect() {
      const idx = document.getElementById('tunnelSelect').value;
      const info = document.getElementById('tunnelInfo');
      const pskField = document.getElementById('pskField');
      const natTField = document.getElementById('natTField');
      const generateBtn = document.getElementById('generateBtn');

      if (idx === '') {
        selectedTunnel = null;
        info.classList.remove('visible');
        pskField.classList.remove('visible');
        natTField.classList.remove('visible');
        generateBtn.disabled = true;
        return;
      }

      selectedTunnel = tunnelsData[idx];

      // Update info panel
      document.getElementById('infoType').innerHTML = '<span class="tunnel-badge ' + selectedTunnel.tunnelType + '">' + selectedTunnel.tunnelType + '</span>';
      document.getElementById('infoCfEndpoint').textContent = selectedTunnel.cloudflare_endpoint;
      document.getElementById('infoCustEndpoint').textContent = selectedTunnel.customer_endpoint;
      document.getElementById('infoInterface').textContent = selectedTunnel.interface_address;
      info.classList.add('visible');

      // Show PSK and NAT-T fields only for IPsec
      if (selectedTunnel.tunnelType === 'ipsec') {
        pskField.classList.add('visible');
        natTField.classList.add('visible');
        generateBtn.disabled = true; // Will enable when PSK entered
        document.getElementById('psk').oninput = function() {
          generateBtn.disabled = !this.value.trim();
        };
      } else {
        pskField.classList.remove('visible');
        natTField.classList.remove('visible');
        generateBtn.disabled = false;
      }
    }

    async function generateConfig() {
      const btn = document.getElementById('generateBtn');
      const useAI = document.getElementById('useAI').checked;
      btn.innerHTML = useAI ? '<div class="spinner"></div> Generating with AI...' : '<div class="spinner"></div> Generating...';
      btn.disabled = true;

      const formData = new FormData();
      formData.append('deviceType', document.getElementById('deviceType').value);
      formData.append('tunnelType', selectedTunnel.tunnelType);
      formData.append('tunnelName', selectedTunnel.name);
      formData.append('cloudflareEndpoint', selectedTunnel.cloudflare_endpoint);
      formData.append('customerEndpoint', selectedTunnel.customer_endpoint);
      formData.append('interfaceAddress', selectedTunnel.interface_address);
      formData.append('tunnelFqdn', selectedTunnel.fqdn || '');
      formData.append('psk', document.getElementById('psk').value || '');
      formData.append('accountId', accountId);
      formData.append('enableNatT', document.getElementById('enableNatT').checked ? 'true' : 'false');

      try {
        const endpoint = useAI ? '/generate-ai' : '/generate';
        const res = await fetch(endpoint, { method: 'POST', body: formData });
        const data = await res.json();

        // Show output
        document.getElementById('outputPlaceholder').style.display = 'none';
        const codeBlock = document.getElementById('codeBlock');
        codeBlock.textContent = data.config;
        codeBlock.classList.add('visible');

        // Show device badge and copy button
        const deviceSelect = document.getElementById('deviceType');
        let deviceLabel = deviceSelect.options[deviceSelect.selectedIndex].text;
        if (data.aiGenerated) deviceLabel += ' (AI)';
        if (data.fallback) deviceLabel += ' (Fallback)';
        document.getElementById('outputDevice').textContent = deviceLabel;
        document.getElementById('outputDevice').style.display = 'block';
        document.getElementById('copyBtn').style.display = 'flex';

        const msg = data.aiGenerated ? 'AI-generated configuration ready' : (data.fallback ? 'Generated (AI fallback to template)' : 'Configuration generated');
        showToast(msg, 'success');

      } catch (e) {
        showToast('Failed to generate configuration', 'error');
      } finally {
        btn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="16 18 22 12 16 6"/><polyline points="8 6 2 12 8 18"/></svg> Generate Configuration';
        btn.disabled = selectedTunnel.tunnelType === 'ipsec' && !document.getElementById('psk').value.trim();
      }
    }

    function copyConfig() {
      const config = document.getElementById('codeBlock').textContent;
      navigator.clipboard.writeText(config);
      showToast('Copied to clipboard', 'success');
    }

    function disconnect() {
      // Reset state
      tunnelsData = [];
      selectedTunnel = null;
      accountId = '';

      // Reset forms
      document.getElementById('accountId').value = '';
      document.getElementById('apiToken').value = '';
      document.getElementById('tunnelSelect').innerHTML = '<option value="">Choose a tunnel...</option>';
      document.getElementById('psk').value = '';
      document.getElementById('enableNatT').checked = false;
      document.getElementById('useAI').checked = false;

      // Reset UI
      document.getElementById('statusDot').classList.remove('connected');
      document.getElementById('statusText').textContent = 'Not connected';

      const connectCard = document.getElementById('connectCard');
      connectCard.classList.remove('connected', 'collapsed');
      const connectBtn = document.getElementById('connectBtn');
      connectBtn.innerHTML = '<svg class="btn-icon" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M15 3h4a2 2 0 0 1 2 2v14a2 2 0 0 1-2 2h-4"/><polyline points="10 17 15 12 10 7"/><line x1="15" y1="12" x2="3" y2="12"/></svg> Connect';
      connectBtn.disabled = false;

      document.getElementById('step1Num').classList.add('active');
      document.getElementById('step1Num').classList.remove('done');
      document.getElementById('step1Num').textContent = '1';

      const configCard = document.getElementById('configCard');
      configCard.style.opacity = '0.5';
      configCard.style.pointerEvents = 'none';
      document.getElementById('step2Num').classList.remove('active');

      document.getElementById('tunnelInfo').classList.remove('visible');
      document.getElementById('pskField').classList.remove('visible');
      document.getElementById('natTField').classList.remove('visible');
      document.getElementById('generateBtn').disabled = true;

      document.getElementById('disconnectBtn').style.display = 'none';

      // Reset output
      document.getElementById('outputPlaceholder').style.display = 'flex';
      document.getElementById('codeBlock').classList.remove('visible');
      document.getElementById('codeBlock').textContent = '';
      document.getElementById('outputDevice').style.display = 'none';
      document.getElementById('copyBtn').style.display = 'none';
    }

    function showToast(message, type = 'success') {
      const toast = document.getElementById('toast');
      const icon = document.getElementById('toastIcon');
      const msg = document.getElementById('toastMessage');

      toast.className = 'toast ' + type;
      msg.textContent = message;

      if (type === 'success') {
        icon.innerHTML = '<path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/>';
      } else {
        icon.innerHTML = '<circle cx="12" cy="12" r="10"/><line x1="12" y1="8" x2="12" y2="12"/><line x1="12" y1="16" x2="12.01" y2="16"/>';
      }

      toast.classList.add('show');
      setTimeout(() => toast.classList.remove('show'), 3000);
    }

    // Allow Enter key to submit
    document.getElementById('apiToken').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') connect();
    });
    document.getElementById('accountId').addEventListener('keypress', function(e) {
      if (e.key === 'Enter') document.getElementById('apiToken').focus();
    });
  </script>
</body>
</html>`;
}
