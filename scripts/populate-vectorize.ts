/**
 * Script to populate Vectorize index with Magic WAN documentation
 * Run with: npx wrangler dev scripts/populate-vectorize.ts --test-scheduled
 * Or deploy and trigger via: curl -X POST https://your-worker.dev/__scheduled
 */

interface Env {
  AI: Ai;
  VECTORIZE: VectorizeIndex;
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

// Pre-extracted documentation chunks from Cloudflare docs
const DOC_CHUNKS: DocChunk[] = [
  // Cisco IOS-XE IPsec
  {
    id: "cisco-ios-ipsec-overview",
    text: `Cisco IOS-XE IPsec Configuration for Magic WAN. Use IKEv2 with DH group 20 (384-bit ECDH). Encryption should be AES-256-CBC or AES-256-GCM. Integrity algorithms: SHA-256, SHA-384, or SHA-512. IKE lifetime: 86400 seconds (24 hours). IPsec lifetime: 28800 seconds (8 hours). Anti-replay must be disabled. MTU: 1450, TCP MSS: 1350.`,
    metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-ios-ipsec-proposal",
    text: `Cisco IOS-XE IKEv2 Proposal Configuration:
crypto ikev2 proposal CF-MWAN-PROPOSAL
  encryption aes-cbc-256
  integrity sha512 sha384 sha256
  group 20 14

The proposal defines encryption (aes-cbc-256), integrity algorithms (sha512, sha384, sha256), and DH groups (20 primary, 14 fallback). Group 20 is 384-bit ECDH.`,
    metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "ikev2-proposal", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-ios-ipsec-profile",
    text: `Cisco IOS-XE IKEv2 Profile Configuration:
crypto ikev2 profile CF-MWAN-PROFILE
  match identity remote address <cloudflare_endpoint> 255.255.255.255
  identity local fqdn <account_id>.ipsec.cloudflare.com
  authentication remote pre-share
  authentication local pre-share
  keyring local CF-MWAN-KEYRING
  lifetime 86400
  dpd 10 3 periodic
  nat force-encap

For NAT-T, add 'nat force-encap' to force UDP encapsulation on port 4500. Use local identity as FQDN format: <account_id>.ipsec.cloudflare.com`,
    metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "ikev2-profile", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-ios-ipsec-transform",
    text: `Cisco IOS-XE IPsec Transform Set:
crypto ipsec transform-set CF-MWAN-TRANSFORM esp-aes 256 esp-sha256-hmac
  mode tunnel

crypto ipsec profile CF-MWAN-IPSEC-PROFILE
  set transform-set CF-MWAN-TRANSFORM
  set ikev2-profile CF-MWAN-PROFILE
  set security-association lifetime kilobytes disable
  set security-association replay disable
  set pfs group20

Anti-replay must be disabled. PFS uses group20. Kilobyte-based lifetime should be disabled.`,
    metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "transform-set", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-ios-ipsec-tunnel",
    text: `Cisco IOS-XE Tunnel Interface:
interface Tunnel1
  description Cloudflare Magic WAN
  ip address <customer_ip> 255.255.255.254
  tunnel source <customer_endpoint>
  tunnel mode ipsec ipv4
  tunnel destination <cloudflare_endpoint>
  tunnel protection ipsec profile CF-MWAN-IPSEC-PROFILE
  tunnel path-mtu-discovery
  ip mtu 1450
  ip tcp adjust-mss 1350
  no shutdown

crypto isakmp invalid-spi-recovery

MTU 1450 and MSS 1350 are required. Enable path-mtu-discovery. Enable invalid-spi-recovery.`,
    metadata: { deviceType: "cisco-ios", tunnelType: "ipsec", section: "tunnel-interface", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-ios-gre-tunnel",
    text: `Cisco IOS-XE GRE Tunnel Configuration:
interface Tunnel1
  description Cloudflare Magic WAN GRE
  ip address <customer_ip> 255.255.255.254
  tunnel source <customer_endpoint>
  tunnel destination <cloudflare_endpoint>
  tunnel mode gre ip
  ip mtu 1476
  ip tcp adjust-mss 1436
  keepalive 10 3
  no shutdown

For GRE tunnels, MTU is 1476 and MSS is 1436. Keepalives should be 10 seconds with 3 retries.`,
    metadata: { deviceType: "cisco-ios", tunnelType: "gre", section: "tunnel-interface", source: "developers.cloudflare.com" }
  },

  // Cisco SD-WAN (Viptela)
  {
    id: "cisco-sdwan-ipsec-overview",
    text: `Cisco SD-WAN (Viptela) IPsec Configuration for Magic WAN. IPsec is only supported on Cisco 8000v in router mode. Use IKEv2 with cipher-suite aes256-cbc-sha256 and group 20. IKE rekey 86400 seconds, IPsec rekey 28800 seconds. Replay window must be 0 (disabled). For NAT-T, add 'nat-t enable' in the IKE section.`,
    metadata: { deviceType: "cisco-sdwan", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-sdwan-ipsec-config",
    text: `Cisco SD-WAN IPsec Interface Configuration:
vpn 0
  interface ipsec1
    description "Cloudflare Magic WAN"
    ip address <customer_ip>/31
    tunnel-source-interface ge0/0
    tunnel-destination <cloudflare_endpoint>
    ike
      version 2
      rekey 86400
      cipher-suite aes256-cbc-sha256
      group 20
      nat-t enable
      authentication-type
        pre-shared-key
          pre-shared-secret <psk>
    ipsec
      rekey 28800
      replay-window 0
      cipher-suite aes256-cbc-sha256
      perfect-forward-secrecy group-20
    mtu 1450
    tcp-mss-adjust 1350
    no shutdown`,
    metadata: { deviceType: "cisco-sdwan", tunnelType: "ipsec", section: "interface-config", source: "developers.cloudflare.com" }
  },
  {
    id: "cisco-sdwan-gre-config",
    text: `Cisco SD-WAN GRE Interface Configuration:
vpn 0
  interface gre1
    description "Cloudflare Magic WAN GRE"
    ip address <customer_ip>/31
    tunnel-source-interface ge0/0
    tunnel-destination <cloudflare_endpoint>
    mtu 1476
    tcp-mss-adjust 1436
    no shutdown

GRE tunnels use MTU 1476 and MSS 1436.`,
    metadata: { deviceType: "cisco-sdwan", tunnelType: "gre", section: "interface-config", source: "developers.cloudflare.com" }
  },

  // Fortinet FortiGate
  {
    id: "fortinet-ipsec-overview",
    text: `Fortinet FortiGate IPsec Configuration for Magic WAN. CRITICAL: Must enable asymmetric routing and set IKE port to 4500. Use IKEv2 with AES-256-GCM and DH group 20. Phase 1 keylife: 86400 seconds. Phase 2 must disable replay. Local ID format: <account_id>.ipsec.cloudflare.com. For NAT-T, set nattraversal enable in phase1-interface.`,
    metadata: { deviceType: "fortinet", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "fortinet-global-settings",
    text: `FortiGate REQUIRED Global Settings:
config system settings
    set asymroute-icmp enable
end

config system global
    set ike-port 4500
end

These settings are MANDATORY. asymroute-icmp must be enabled. IKE port must be 4500.`,
    metadata: { deviceType: "fortinet", tunnelType: "ipsec", section: "global-settings", source: "developers.cloudflare.com" }
  },
  {
    id: "fortinet-phase1",
    text: `FortiGate Phase 1 Configuration:
config vpn ipsec phase1-interface
    edit "CF-MWAN"
        set interface "wan1"
        set ike-version 2
        set peertype any
        set net-device enable
        set proposal aes256gcm-prfsha512 aes256gcm-prfsha384 aes256gcm-prfsha256
        set dhgrp 20
        set remote-gw <cloudflare_endpoint>
        set psksecret <psk>
        set keylife 86400
        set nattraversal enable
        set localid "<account_id>.ipsec.cloudflare.com"
    next
end

Use AES-256-GCM proposals. DH group 20. Key lifetime 86400 seconds. Set localid to account FQDN.`,
    metadata: { deviceType: "fortinet", tunnelType: "ipsec", section: "phase1", source: "developers.cloudflare.com" }
  },
  {
    id: "fortinet-phase2",
    text: `FortiGate Phase 2 Configuration:
config vpn ipsec phase2-interface
    edit "CF-MWAN-P2"
        set phase1name "CF-MWAN"
        set proposal aes256gcm
        set dhgrp 20
        set replay disable
        set keepalive enable
        set auto-negotiate enable
    next
end

CRITICAL: replay must be set to disable. PFS uses DH group 20.`,
    metadata: { deviceType: "fortinet", tunnelType: "ipsec", section: "phase2", source: "developers.cloudflare.com" }
  },
  {
    id: "fortinet-gre",
    text: `FortiGate GRE Configuration:
config system gre-tunnel
    edit "CF-MWAN-GRE"
        set interface "wan1"
        set remote-gw <cloudflare_endpoint>
        set local-gw <customer_endpoint>
    next
end

config system interface
    edit "CF-MWAN-GRE"
        set ip <customer_ip> 255.255.255.254
        set allowaccess ping
        set mtu-override enable
        set mtu 1476
    next
end

GRE tunnels use MTU 1476.`,
    metadata: { deviceType: "fortinet", tunnelType: "gre", section: "gre-config", source: "developers.cloudflare.com" }
  },

  // Palo Alto Networks
  {
    id: "paloalto-ipsec-overview",
    text: `Palo Alto Networks IPsec Configuration for Magic WAN. Use IKEv2 with DH group 20 and AES-256-CBC encryption. IKE lifetime: 24 hours. IPsec lifetime: 8 hours. Anti-replay must be disabled. For NAT-T, configure nat-traversal enable on the IKE gateway. Local identity uses FQDN format: <account_id>.ipsec.cloudflare.com`,
    metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "paloalto-ike-crypto",
    text: `Palo Alto IKE Crypto Profile:
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto hash sha512 sha384 sha256
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto dh-group group20
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto encryption aes-256-cbc
set network ike crypto-profiles ike-crypto-profiles CF_IKE_Crypto lifetime hours 24

Use SHA-512/384/256 for hash. DH group 20. AES-256-CBC encryption. 24 hour lifetime.`,
    metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "ike-crypto", source: "developers.cloudflare.com" }
  },
  {
    id: "paloalto-ipsec-crypto",
    text: `Palo Alto IPsec Crypto Profile:
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto esp authentication sha256 sha1
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto esp encryption aes-256-cbc
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto dh-group group20
set network ike crypto-profiles ipsec-crypto-profiles CF_IPsec_Crypto lifetime hours 8

ESP authentication SHA-256. ESP encryption AES-256-CBC. PFS group 20. 8 hour lifetime.`,
    metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "ipsec-crypto", source: "developers.cloudflare.com" }
  },
  {
    id: "paloalto-ike-gateway",
    text: `Palo Alto IKE Gateway:
set network ike gateway CF_MWAN_GW authentication pre-shared-key key <psk>
set network ike gateway CF_MWAN_GW protocol ikev2 dpd enable yes
set network ike gateway CF_MWAN_GW protocol ikev2 ike-crypto-profile CF_IKE_Crypto
set network ike gateway CF_MWAN_GW protocol version ikev2
set network ike gateway CF_MWAN_GW protocol ikev2 nat-traversal enable
set network ike gateway CF_MWAN_GW local-address interface ethernet1/1
set network ike gateway CF_MWAN_GW local-address ip <customer_endpoint>
set network ike gateway CF_MWAN_GW peer-address ip <cloudflare_endpoint>
set network ike gateway CF_MWAN_GW local-id type fqdn id <account_id>.ipsec.cloudflare.com

Enable DPD. Use IKEv2 only. Configure NAT-T. Set local-id as FQDN.`,
    metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "ike-gateway", source: "developers.cloudflare.com" }
  },
  {
    id: "paloalto-tunnel-ipsec",
    text: `Palo Alto Tunnel Interface and IPsec Tunnel:
set network interface tunnel units tunnel.1 ip <customer_ip>/31
set network interface tunnel units tunnel.1 mtu 1450
set network interface tunnel units tunnel.1 comment "Cloudflare Magic WAN"
set network profiles interface-management-profile Allow_Ping ping yes
set network interface tunnel units tunnel.1 interface-management-profile Allow_Ping

set network tunnel ipsec CF_MWAN_IPsec auto-key ike-gateway CF_MWAN_GW
set network tunnel ipsec CF_MWAN_IPsec auto-key ipsec-crypto-profile CF_IPsec_Crypto
set network tunnel ipsec CF_MWAN_IPsec tunnel-interface tunnel.1
set network tunnel ipsec CF_MWAN_IPsec anti-replay no

set zone Cloudflare network layer3 tunnel.1

MTU 1450. CRITICAL: anti-replay must be no.`,
    metadata: { deviceType: "paloalto", tunnelType: "ipsec", section: "tunnel-config", source: "developers.cloudflare.com" }
  },
  {
    id: "paloalto-gre",
    text: `Palo Alto GRE Configuration:
set network interface tunnel units tunnel.1 ip <customer_ip>/31
set network interface tunnel units tunnel.1 mtu 1476
set zone Cloudflare network layer3 tunnel.1

GRE on Palo Alto uses tunnel interface with MTU 1476. Native GRE support varies by PAN-OS version.`,
    metadata: { deviceType: "paloalto", tunnelType: "gre", section: "gre-config", source: "developers.cloudflare.com" }
  },

  // Juniper SRX
  {
    id: "juniper-ipsec-overview",
    text: `Juniper SRX IPsec Configuration for Magic WAN. Use IKEv2 only (version v2-only). DH group 20 with AES-256-CBC. IKE lifetime: 86400 seconds. IPsec lifetime: 28800 seconds. Anti-replay must be disabled (no-anti-replay). For NAT-T, set nat-keepalive 10 on the IKE gateway.`,
    metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "juniper-ike-proposal",
    text: `Juniper SRX IKE Proposal and Policy:
set security ike proposal cf_ike_prop authentication-method pre-shared-keys
set security ike proposal cf_ike_prop dh-group group20
set security ike proposal cf_ike_prop authentication-algorithm sha-256
set security ike proposal cf_ike_prop encryption-algorithm aes-256-cbc
set security ike proposal cf_ike_prop lifetime-seconds 86400

set security ike policy cf_ike_pol mode main
set security ike policy cf_ike_pol proposals cf_ike_prop
set security ike policy cf_ike_pol pre-shared-key ascii-text "<psk>"

DH group 20, SHA-256 auth, AES-256-CBC encryption, 86400 second lifetime.`,
    metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "ike-proposal", source: "developers.cloudflare.com" }
  },
  {
    id: "juniper-ike-gateway",
    text: `Juniper SRX IKE Gateway:
set security ike gateway cf_gw ike-policy cf_ike_pol
set security ike gateway cf_gw address <cloudflare_endpoint>
set security ike gateway cf_gw external-interface ge-0/0/0.0
set security ike gateway cf_gw local-address <customer_endpoint>
set security ike gateway cf_gw version v2-only
set security ike gateway cf_gw nat-keepalive 10
set security ike gateway cf_gw local-identity fqdn <account_id>.ipsec.cloudflare.com

Use v2-only for IKEv2. nat-keepalive 10 for NAT traversal. Set local-identity as FQDN.`,
    metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "ike-gateway", source: "developers.cloudflare.com" }
  },
  {
    id: "juniper-ipsec-proposal",
    text: `Juniper SRX IPsec Proposal and Policy:
set security ipsec proposal cf_ipsec_prop protocol esp
set security ipsec proposal cf_ipsec_prop authentication-algorithm hmac-sha-256-128
set security ipsec proposal cf_ipsec_prop encryption-algorithm aes-256-cbc
set security ipsec proposal cf_ipsec_prop lifetime-seconds 28800

set security ipsec policy cf_ipsec_pol perfect-forward-secrecy keys group20
set security ipsec policy cf_ipsec_pol proposals cf_ipsec_prop

ESP with HMAC-SHA-256-128, AES-256-CBC, 28800 second lifetime, PFS group 20.`,
    metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "ipsec-proposal", source: "developers.cloudflare.com" }
  },
  {
    id: "juniper-vpn-tunnel",
    text: `Juniper SRX VPN and Tunnel Interface:
set security ipsec vpn cf_vpn bind-interface st0.0
set security ipsec vpn cf_vpn ike gateway cf_gw
set security ipsec vpn cf_vpn ike no-anti-replay
set security ipsec vpn cf_vpn ike ipsec-policy cf_ipsec_pol
set security ipsec vpn cf_vpn establish-tunnels immediately

set interfaces st0 unit 0 description "Cloudflare Magic WAN"
set interfaces st0 unit 0 family inet address <customer_ip>/31

set security zones security-zone cloudflare interfaces st0.0 host-inbound-traffic system-services all
set security zones security-zone cloudflare interfaces st0.0 host-inbound-traffic protocols all

CRITICAL: no-anti-replay must be set. Use st0 interface.`,
    metadata: { deviceType: "juniper", tunnelType: "ipsec", section: "vpn-tunnel", source: "developers.cloudflare.com" }
  },
  {
    id: "juniper-gre",
    text: `Juniper SRX GRE Configuration:
set interfaces gr-0/0/0 unit 0 description "Cloudflare Magic WAN GRE"
set interfaces gr-0/0/0 unit 0 tunnel source <customer_endpoint>
set interfaces gr-0/0/0 unit 0 tunnel destination <cloudflare_endpoint>
set interfaces gr-0/0/0 unit 0 family inet address <customer_ip>/31
set interfaces gr-0/0/0 unit 0 family inet mtu 1476

set security zones security-zone cloudflare interfaces gr-0/0/0.0 host-inbound-traffic system-services all
set security zones security-zone cloudflare interfaces gr-0/0/0.0 host-inbound-traffic protocols all

GRE uses gr-0/0/0 interface with MTU 1476.`,
    metadata: { deviceType: "juniper", tunnelType: "gre", section: "gre-config", source: "developers.cloudflare.com" }
  },

  // Ubiquiti / VyOS
  {
    id: "ubiquiti-ipsec-overview",
    text: `Ubiquiti EdgeRouter / VyOS IPsec Configuration for Magic WAN. Use IKEv2 with AES-256 and SHA-256. DH group 20. IKE lifetime: 86400 seconds. ESP lifetime: 28800 seconds. DPD with 30 second interval. For NAT-T, use force-udp-encapsulation on the site-to-site peer.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "overview", source: "developers.cloudflare.com" }
  },
  {
    id: "ubiquiti-ike-group",
    text: `Ubiquiti/VyOS IKE Group:
set vpn ipsec ike-group CF-IKE proposal 1 encryption aes256
set vpn ipsec ike-group CF-IKE proposal 1 hash sha256
set vpn ipsec ike-group CF-IKE proposal 1 dh-group 20
set vpn ipsec ike-group CF-IKE lifetime 86400
set vpn ipsec ike-group CF-IKE key-exchange ikev2
set vpn ipsec ike-group CF-IKE dead-peer-detection action restart
set vpn ipsec ike-group CF-IKE dead-peer-detection interval 30
set vpn ipsec ike-group CF-IKE dead-peer-detection timeout 120

AES-256, SHA-256, DH group 20, 86400 lifetime, IKEv2. DPD with restart action.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "ike-group", source: "developers.cloudflare.com" }
  },
  {
    id: "ubiquiti-esp-group",
    text: `Ubiquiti/VyOS ESP Group:
set vpn ipsec esp-group CF-ESP proposal 1 encryption aes256
set vpn ipsec esp-group CF-ESP proposal 1 hash sha256
set vpn ipsec esp-group CF-ESP lifetime 28800
set vpn ipsec esp-group CF-ESP pfs dh-group20
set vpn ipsec esp-group CF-ESP mode tunnel

AES-256, SHA-256, 28800 lifetime, PFS with DH group 20, tunnel mode.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "esp-group", source: "developers.cloudflare.com" }
  },
  {
    id: "ubiquiti-peer",
    text: `Ubiquiti/VyOS Site-to-Site Peer:
set vpn ipsec site-to-site peer <cloudflare_endpoint> description "Cloudflare Magic WAN"
set vpn ipsec site-to-site peer <cloudflare_endpoint> authentication mode pre-shared-secret
set vpn ipsec site-to-site peer <cloudflare_endpoint> authentication pre-shared-secret "<psk>"
set vpn ipsec site-to-site peer <cloudflare_endpoint> ike-group CF-IKE
set vpn ipsec site-to-site peer <cloudflare_endpoint> local-address <customer_endpoint>
set vpn ipsec site-to-site peer <cloudflare_endpoint> vti bind vti0
set vpn ipsec site-to-site peer <cloudflare_endpoint> vti esp-group CF-ESP
set vpn ipsec site-to-site peer <cloudflare_endpoint> force-udp-encapsulation

set vpn ipsec ipsec-interfaces interface eth0

Use VTI (vti0). For NAT-T, add force-udp-encapsulation.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "peer-config", source: "developers.cloudflare.com" }
  },
  {
    id: "ubiquiti-vti",
    text: `Ubiquiti/VyOS VTI Interface:
set interfaces vti vti0 description "Cloudflare Magic WAN"
set interfaces vti vti0 address <customer_ip>/31
set interfaces vti vti0 mtu 1450

VTI interface with /31 addressing and MTU 1450.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "ipsec", section: "vti-interface", source: "developers.cloudflare.com" }
  },
  {
    id: "ubiquiti-gre",
    text: `Ubiquiti/VyOS GRE Configuration:
set interfaces tunnel tun0 description "Cloudflare Magic WAN GRE"
set interfaces tunnel tun0 encapsulation gre
set interfaces tunnel tun0 local-ip <customer_endpoint>
set interfaces tunnel tun0 remote-ip <cloudflare_endpoint>
set interfaces tunnel tun0 address <customer_ip>/31
set interfaces tunnel tun0 mtu 1476

GRE uses tunnel interface with encapsulation gre and MTU 1476.`,
    metadata: { deviceType: "ubiquiti", tunnelType: "gre", section: "gre-config", source: "developers.cloudflare.com" }
  },

  // General IPsec parameters
  {
    id: "mwan-ipsec-params",
    text: `Magic WAN IPsec Recommended Parameters:
- IKE Version: IKEv2 only (required)
- DH Group: 20 (384-bit ECDH) - primary, 14 as fallback
- Encryption: AES-256-CBC or AES-256-GCM
- Integrity/Hash: SHA-256, SHA-384, or SHA-512
- IKE/Phase 1 Lifetime: 86400 seconds (24 hours)
- IPsec/Phase 2 Lifetime: 28800 seconds (8 hours)
- Anti-Replay: MUST be disabled (critical for anycast)
- PFS: Group 20
- MTU: 1450
- TCP MSS: 1350
- NAT-T: Use UDP port 4500 when behind NAT`,
    metadata: { deviceType: "all", tunnelType: "ipsec", section: "parameters", source: "developers.cloudflare.com" }
  },
  {
    id: "mwan-gre-params",
    text: `Magic WAN GRE Recommended Parameters:
- MTU: 1476
- TCP MSS: 1436
- Keepalive: 10 seconds with 3 retries (recommended)
- Tunnel mode: GRE over IP

GRE tunnels are simpler but don't provide encryption. Use IPsec for encrypted connectivity.`,
    metadata: { deviceType: "all", tunnelType: "gre", section: "parameters", source: "developers.cloudflare.com" }
  },
  {
    id: "mwan-identity",
    text: `Magic WAN IKE Identity Configuration:
- Local Identity Format: <account_id>.ipsec.cloudflare.com
- Identity Type: FQDN
- The account ID is your Cloudflare account ID
- For tunnel-specific identity: <tunnel_id>.<account_id>.ipsec.cloudflare.com`,
    metadata: { deviceType: "all", tunnelType: "ipsec", section: "identity", source: "developers.cloudflare.com" }
  },
  {
    id: "mwan-anti-replay",
    text: `Magic WAN Anti-Replay Requirement:
Anti-replay protection MUST be disabled on the customer device. This is because Cloudflare uses anycast routing, and packets may arrive at different data centers with non-sequential sequence numbers. Failing to disable anti-replay will cause intermittent packet drops and connectivity issues.

Device-specific settings:
- Cisco IOS: set security-association replay disable
- Fortinet: set replay disable
- Palo Alto: set anti-replay no
- Juniper: set no-anti-replay
- Viptela: replay-window 0`,
    metadata: { deviceType: "all", tunnelType: "ipsec", section: "anti-replay", source: "developers.cloudflare.com" }
  }
];

export default {
  async scheduled(event: ScheduledEvent, env: Env, ctx: ExecutionContext): Promise<void> {
    await populateIndex(env);
  },

  async fetch(request: Request, env: Env): Promise<Response> {
    const url = new URL(request.url);

    if (url.pathname === "/populate" && request.method === "POST") {
      try {
        const result = await populateIndex(env);
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

    return new Response("POST /populate to add documents to Vectorize", {
      headers: { "Content-Type": "text/plain" },
    });
  },
};

async function populateIndex(env: Env): Promise<{ success: boolean; inserted: number }> {
  const vectors: VectorizeVector[] = [];

  // Generate embeddings for each chunk
  for (const chunk of DOC_CHUNKS) {
    const embedding = await env.AI.run("@cf/baai/bge-base-en-v1.5", {
      text: chunk.text,
    });

    if (embedding.data && embedding.data[0]) {
      vectors.push({
        id: chunk.id,
        values: embedding.data[0],
        metadata: chunk.metadata,
      });
    }
  }

  // Insert vectors in batches
  const batchSize = 100;
  let inserted = 0;

  for (let i = 0; i < vectors.length; i += batchSize) {
    const batch = vectors.slice(i, i + batchSize);
    await env.VECTORIZE.upsert(batch);
    inserted += batch.length;
  }

  return { success: true, inserted };
}
