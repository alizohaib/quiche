# AnyIP for QUIX Address Hopping on AWS

## Summary

The Linux kernel's AnyIP feature allows claiming an entire IPv6 subnet with a single command, enabling `sendmsg()` with `IPV6_PKTINFO` to use any address in the prefix as the source. This replaces the need for 256+ individual `ip addr add` commands.

**However**, on AWS it requires disabling source/destination checking on the EC2 instance. Without this, AWS's VPC hypervisor silently drops packets whose source address isn't explicitly assigned to the ENI.

## Setup Commands

### Proxy (server-side hopping)

```bash
# Claim the entire /80 prefix for outbound source selection
sudo ip -6 route add local 2600:1f18:6da3:7600:8bc4::/80 dev lo

# Allow sendmsg() to use addresses not explicitly assigned to an interface
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
```

### Client (client-side hopping)

```bash
# Same approach if client needs to hop from a delegated prefix
sudo ip -6 route add local 2600:1f1c:2d:e700:12f2::/80 dev lo
sudo sysctl -w net.ipv6.ip_nonlocal_bind=1
```

**Note:** Client-side hopping in the current code randomizes the last 8 bits of the current self_address. If the client's primary address is used (no delegated prefix addresses on the interface), it hops within its own /120 neighborhood, which works without any extra setup.

## AWS Requirement: Disable Source/Destination Check

Without this, packets leave the kernel correctly (visible on tcpdump at the sender) but are dropped by the VPC dataplane before reaching the peer.

Disable via:
- **AWS Console:** EC2 > Instance > Actions > Networking > Change source/destination check > Disable
- **AWS CLI:** `aws ec2 modify-instance-attribute --instance-id <id> --no-source-dest-check`

Instance affected: Proxy (`i-08c26e60d5a6b80c5` / `3.88.159.86` in us-east-1)

## How It Works

1. `ip -6 route add local <prefix> dev lo` adds a route in the kernel's **local** routing table, telling it "all addresses in this prefix belong to this machine"
2. The kernel will:
   - Accept **incoming** packets destined to any address in the prefix (delivers to local sockets)
   - Respond to Neighbor Solicitations for any address in the prefix
   - Allow `bind()` to any address in the prefix
3. `net.ipv6.ip_nonlocal_bind=1` additionally allows `sendmsg()` with `IPV6_PKTINFO` to set any locally-routed address as the packet source, even if it's not assigned to the outgoing interface

## Why Individual `ip addr add` Worked Without Disabling Source/Dest Check

When you run `ip -6 addr add <addr>/128 dev ens5`, AWS's internal ENI monitoring agent detects the new address assignment and adds it to the VPC's source address whitelist for that ENI. This happens transparently.

AnyIP on `lo` is invisible to this mechanism — AWS only monitors actual interface address assignments, not local routing table entries.

## Comparison

| Approach | Commands | Address Space | AWS src/dst check | Works |
|----------|----------|---------------|-------------------|-------|
| Individual `/128` on `ens5` | 256 commands | 256 addresses | Can stay enabled | Yes |
| AnyIP on `lo` + `ip_nonlocal_bind` | 2 commands | 2^48 addresses (/80) | Must be disabled | Yes |

## Verified Results

With AnyIP + source/dest check disabled on the proxy:
- **152 unique source addresses** observed in 15-second transfer (server hopping every 100ms)
- Full /80 address space available (not limited to 256)
- Addresses like `8bc4::dead`, `8bc4:abcd:ef01:2345`, `8bc4:ffff:ffff:ffff` all work

## When AnyIP Works Without Any Cloud-Specific Configuration

- Bare metal servers (no hypervisor filtering)
- VPS providers without source filtering (Vultr, Hetzner, OVH, etc.)
- AWS with source/destination check disabled
- Any environment where the upstream router forwards the prefix and doesn't inspect source addresses

## Script Integration

In `run-ablation-aws.sh`, the proxy setup can use either approach:

```bash
# Option A: AnyIP (requires source/dest check disabled on AWS)
sudo ip -6 route add local ${PROXY_PREFIX}::/80 dev lo 2>/dev/null || true
sudo sysctl -qw net.ipv6.ip_nonlocal_bind=1

# Option B: Individual addresses (works with default AWS settings)
for i in $(seq 0 255); do
  sudo ip -6 addr add ${PROXY_PREFIX}::$(printf '%x' $i)/128 dev ens5 nodad 2>/dev/null || true
done
```
