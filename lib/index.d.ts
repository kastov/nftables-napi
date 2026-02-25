/**
 * Native nftables manager for remnawave firewall.
 * Requires CAP_NET_ADMIN or root privileges.
 */
/**
 * Firewall strategy for blacklisted IPs.
 */
export type FirewallStrategy = 'drop' | 'reject' | 'tcp-reset';

export interface NftManagerOptions {
    /**
     * How to handle packets from blacklisted IPs.
     * - 'drop': silently discard packets (no response sent to client)
     * - 'reject': respond with ICMP port-unreachable (default)
     * - 'tcp-reset': TCP RST for TCP traffic, ICMP reject for non-TCP
     * @default 'reject'
     */
    strategy?: FirewallStrategy;
}

export class NftManager {
    constructor(options?: NftManagerOptions);

    /**
     * Creates both IPv4 (table ip remnawave) and IPv6 (table ip6 remnawave6)
     * tables with blacklist sets and filter chains.
     * Idempotent — destroys existing tables first, then recreates.
     * @throws {Error} if nftables command fails
     */
    createTable(): Promise<void>;

    /**
     * Adds an IP address to the blacklist with a timeout.
     * Auto-detects IPv4 vs IPv6 and routes to the correct table/set.
     *
     * @param ip - IPv4 or IPv6 address (e.g., "1.2.3.4" or "2001:db8::1")
     * @param timeout - Duration string: number + unit (s/m/h/d), e.g., "10m", "30s", "2h", "7d"
     * @throws {TypeError} if arguments are missing or wrong type
     * @throws {Error} if IP is invalid, timeout format is wrong, or nftables command fails
     */
    addAddress(ip: string, timeout: string): Promise<void>;

    /**
     * Removes an IP address from the blacklist.
     * Auto-detects IPv4 vs IPv6. Idempotent — no error if IP not in set.
     *
     * @param ip - IPv4 or IPv6 address to remove
     * @throws {TypeError} if argument is missing or wrong type
     * @throws {Error} if IP is invalid or nftables command fails
     */
    removeAddress(ip: string): Promise<void>;

    /**
     * Adds multiple IP addresses to the blacklist in bulk with a timeout.
     * Auto-detects IPv4 vs IPv6 for each address and routes to the correct table/set.
     * Addresses are batched into chunks for efficient netlink communication.
     *
     * @param ips - Array of IPv4 or IPv6 addresses (e.g., ["1.2.3.4", "2001:db8::1"])
     * @param timeout - Duration string: number + unit (s/m/h/d), e.g., "10m", "30s", "2h", "7d"
     *
     * **Note:** Addresses are processed in chunks. If a chunk fails after earlier
     * chunks succeeded, previously added addresses remain committed (nftables
     * does not support rollback). Retrying may cause some addresses to have
     * refreshed timeouts.
     *
     * @throws {TypeError} if arguments are missing, wrong type, or array contains non-strings
     * @throws {Error} if any IP is invalid, timeout format is wrong, or nftables command fails
     */
    addAddresses(ips: string[], timeout: string): Promise<void>;

    /**
     * Removes multiple IP addresses from the blacklist in bulk.
     * Auto-detects IPv4 vs IPv6 for each address. Idempotent — no error if IPs are not in set.
     * Addresses are batched into chunks for efficient netlink communication.
     *
     * @param ips - Array of IPv4 or IPv6 addresses to remove
     *
     * **Note:** Addresses are processed in chunks. If a chunk fails after earlier
     * chunks succeeded, previously removed addresses remain removed. Since removal
     * is idempotent, retrying the full operation is safe.
     *
     * @throws {TypeError} if argument is missing, wrong type, or array contains non-strings
     * @throws {Error} if any IP is invalid or nftables command fails
     */
    removeAddresses(ips: string[]): Promise<void>;

    /**
     * Deletes both IPv4 and IPv6 remnawave tables.
     * Idempotent — no error if tables don't exist.
     * @throws {Error} if nftables command fails
     */
    deleteTable(): Promise<void>;
}
