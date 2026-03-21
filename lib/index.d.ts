/**
 * Native nftables manager for Linux firewall.
 * Manages IPv4/IPv6 tables with dynamic sets and CIDR ranges via libnftnl + libmnl (direct netlink, no nft CLI).
 * Requires CAP_NET_ADMIN or root privileges.
 */

/** Constructor options. */
export interface NftManagerOptions {
    /** Base table name. IPv6 table auto-appends '6'. */
    tableName: string;
    /**
     * Ingress IP set names (≥1 required). Block by source address.
     * Rules: log prefix "<setName>: " + named counter + drop on input and forward chains.
     * IPv6 sets auto-append '6'.
     */
    ingressAddrSets: string[];
    /**
     * Egress IP set names (optional). Block by destination address.
     * Rules: named counter + drop on output chain (no log).
     * IPv6 sets auto-append '6'.
     */
    egressAddrSets?: string[];
    /**
     * Egress port set names (optional). Block by tcp/udp destination port.
     * Rules: single concatenated (proto . port) lookup + named counter + drop on output chain (no log).
     * Port is added to BOTH IPv4 and IPv6 tables (ports are family-independent).
     * IPv6 sets auto-append '6'.
     */
    egressPortSets?: string[];
}

/** Options for adding a single address. */
export interface AddAddressOptions {
    /** IPv4/IPv6 address or CIDR (e.g., "1.2.3.4", "10.0.0.0/8", "2001:db8::/32"). */
    ip: string;
    /** Target set name (must match one from constructor's ingressAddrSets or egressAddrSets). */
    set: string;
    /** Timeout in seconds. Omit for permanent. */
    timeout?: number;
}

/** Options for removing a single address. */
export interface RemoveAddressOptions {
    /** IPv4/IPv6 address or CIDR to remove (must match exactly as added). */
    ip: string;
    /** Target set name (must match one from constructor's ingressAddrSets or egressAddrSets). */
    set: string;
}

/** Options for bulk adding addresses. */
export interface AddAddressesOptions {
    /** Array of IPv4/IPv6 addresses or CIDRs. */
    ips: string[];
    /** Target set name (must match one from constructor's ingressAddrSets or egressAddrSets). */
    set: string;
    /** Timeout in seconds. Omit for permanent. */
    timeout?: number;
}

/** Options for bulk removing addresses. */
export interface RemoveAddressesOptions {
    /** Array of IPv4/IPv6 addresses or CIDRs to remove. */
    ips: string[];
    /** Target set name (must match one from constructor's ingressAddrSets or egressAddrSets). */
    set: string;
}

/** Options for adding a single port. */
export interface AddPortOptions {
    /** Port number (0-65535). */
    port: number;
    /** Target port set name (must match one from constructor's egressPortSets). */
    set: string;
    /** Protocol: 'tcp', 'udp', or omit for both. Default: both. */
    protocol?: 'tcp' | 'udp';
    /** Timeout in seconds. Omit for permanent. */
    timeout?: number;
}

/** Options for removing a single port. */
export interface RemovePortOptions {
    /** Port number (0-65535). */
    port: number;
    /** Target port set name (must match one from constructor's egressPortSets). */
    set: string;
    /** Protocol: 'tcp', 'udp', or omit for both. Default: both. */
    protocol?: 'tcp' | 'udp';
}

/** Options for bulk adding ports. */
export interface AddPortsOptions {
    /** Array of port numbers (0-65535). */
    ports: number[];
    /** Target port set name (must match one from constructor's egressPortSets). */
    set: string;
    /** Protocol: 'tcp', 'udp', or omit for both. Default: both. */
    protocol?: 'tcp' | 'udp';
    /** Timeout in seconds. Omit for permanent. */
    timeout?: number;
}

/** Options for bulk removing ports. */
export interface RemovePortsOptions {
    /** Array of port numbers (0-65535). */
    ports: number[];
    /** Target port set name (must match one from constructor's egressPortSets). */
    set: string;
    /** Protocol: 'tcp', 'udp', or omit for both. Default: both. */
    protocol?: 'tcp' | 'udp';
}

export class NftManager {
    /**
     * Creates a new NftManager instance.
     * Opens a netlink socket and validates configuration.
     *
     * @param options - Required configuration with table name and set names.
     * @throws {TypeError} if options are missing or have wrong types
     * @throws {Error} if netlink socket cannot be opened (missing CAP_NET_ADMIN)
     */
    constructor(options: NftManagerOptions);

    /**
     * Creates IPv4 and IPv6 tables with all configured sets, chains, named counters, and filter rules.
     * Idempotent — destroys existing tables first, then recreates.
     *
     * Creates:
     * - Named counter "processed" (global traffic counter per chain)
     * - Named counter per set (blocked traffic counter)
     * - Input chain with log + counter + drop rules (for ingressAddrSets)
     * - Forward chain with log + counter + drop rules (for ingressAddrSets)
     * - Output chain with counter + drop rules (for egressAddrSets and egressPortSets, no log)
     * - Per-element counters on all sets
     *
     * @throws {Error} if nftables operation fails
     */
    createTable(): Promise<void>;

    /**
     * Deletes both IPv4 and IPv6 tables.
     * Idempotent — no error if tables don't exist.
     *
     * @throws {Error} if nftables operation fails
     */
    deleteTable(): Promise<void>;

    /**
     * Adds an IP address or CIDR range to a set.
     * Auto-detects IPv4 vs IPv6 and routes to the correct table/set. Accepts CIDR notation (e.g., "10.0.0.0/8").
     * Works with both input sets (ingressAddrSets) and output sets (egressAddrSets).
     *
     * @param options - Address, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if IP is invalid, set name is unknown, or nftables operation fails
     */
    addAddress(options: AddAddressOptions): Promise<void>;

    /**
     * Removes an IP address or CIDR range from a set.
     * Idempotent — no error if IP is not in the set.
     * Works with both input sets (ingressAddrSets) and output sets (egressAddrSets).
     *
     * @param options - Address and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if IP is invalid, set name is unknown, or nftables operation fails
     */
    removeAddress(options: RemoveAddressOptions): Promise<void>;

    /**
     * Adds multiple IP addresses or CIDR ranges to a set in bulk.
     * Empty arrays are a no-op.
     *
     * @param options - Array of addresses, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any IP is invalid, set name is unknown, or nftables operation fails
     */
    addAddresses(options: AddAddressesOptions): Promise<void>;

    /**
     * Removes multiple IP addresses or CIDR ranges from a set in bulk.
     * Idempotent — no error if IPs are not in the set.
     * Empty arrays are a no-op.
     *
     * @param options - Array of addresses and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any IP is invalid, set name is unknown, or nftables operation fails
     */
    removeAddresses(options: RemoveAddressesOptions): Promise<void>;

    /**
     * Adds a port to an output port set.
     * Port is added to BOTH IPv4 and IPv6 tables (ports are family-independent).
     * When protocol is omitted, two elements are added: tcp + udp.
     * When protocol is 'tcp' or 'udp', one element with that protocol is added.
     *
     * @param options - Port number, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if port is invalid, set name is unknown, or nftables operation fails
     */
    addPort(options: AddPortOptions): Promise<void>;

    /**
     * Removes a port from an output port set.
     * Idempotent — no error if port is not in the set.
     * Port is removed from BOTH IPv4 and IPv6 tables.
     *
     * @param options - Port number and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if port is invalid, set name is unknown, or nftables operation fails
     */
    removePort(options: RemovePortOptions): Promise<void>;

    /**
     * Adds multiple ports to an output port set in bulk.
     * Ports are added to BOTH IPv4 and IPv6 tables.
     * Empty arrays are a no-op.
     *
     * @param options - Array of port numbers, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any port is invalid, set name is unknown, or nftables operation fails
     */
    addPorts(options: AddPortsOptions): Promise<void>;

    /**
     * Removes multiple ports from an output port set in bulk.
     * Idempotent — no error if ports are not in the set.
     * Ports are removed from BOTH IPv4 and IPv6 tables.
     * Empty arrays are a no-op.
     *
     * @param options - Array of port numbers and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any port is invalid, set name is unknown, or nftables operation fails
     */
    removePorts(options: RemovePortsOptions): Promise<void>;
}
