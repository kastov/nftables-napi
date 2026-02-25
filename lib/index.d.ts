/**
 * Native nftables manager for Linux firewall.
 * Manages IPv4/IPv6 blacklist/droplist tables via libnftnl + libmnl (direct netlink, no nft CLI).
 * Requires CAP_NET_ADMIN or root privileges.
 */

/** Target set for address operations. */
export type TargetSet = 'blacklist' | 'droplist';

/** Constructor options. All fields are required — no defaults. */
export interface NftManagerOptions {
    /** Base table name. IPv6 table auto-appends '6'. */
    tableName: string;
    /** Blacklist set name. IPv6 set auto-appends '6'. */
    blacklistSetName: string;
    /** Droplist set name. IPv6 set auto-appends '6'. */
    droplistSetName: string;
}

/** Options for adding a single address. */
export interface AddAddressOptions {
    /** IPv4 or IPv6 address (e.g., "1.2.3.4" or "2001:db8::1"). */
    ip: string;
    /** Target set: 'blacklist' or 'droplist'. */
    set: TargetSet;
    /** Timeout in seconds. Omit for permanent ban. */
    timeout?: number;
}

/** Options for removing a single address. */
export interface RemoveAddressOptions {
    /** IPv4 or IPv6 address to remove. */
    ip: string;
    /** Target set: 'blacklist' or 'droplist'. */
    set: TargetSet;
}

/** Options for bulk adding addresses. */
export interface AddAddressesOptions {
    /** Array of IPv4/IPv6 addresses. */
    ips: string[];
    /** Target set: 'blacklist' or 'droplist'. */
    set: TargetSet;
    /** Timeout in seconds. Omit for permanent ban. */
    timeout?: number;
}

/** Options for bulk removing addresses. */
export interface RemoveAddressesOptions {
    /** Array of IPv4/IPv6 addresses to remove. */
    ips: string[];
    /** Target set: 'blacklist' or 'droplist'. */
    set: TargetSet;
}

export class NftManager {
    /**
     * Creates a new NftManager instance.
     * Opens a netlink socket and validates configuration.
     *
     * @param options - Required configuration with table and set names.
     * @throws {TypeError} if options are missing or have wrong types
     * @throws {Error} if netlink socket cannot be opened (missing CAP_NET_ADMIN)
     */
    constructor(options: NftManagerOptions);

    /**
     * Creates IPv4 and IPv6 tables with blacklist/droplist sets and filter chains.
     * Idempotent — destroys existing tables first, then recreates.
     */
    createTable(): Promise<void>;

    /**
     * Deletes both IPv4 and IPv6 tables.
     * Idempotent — no error if tables don't exist.
     */
    deleteTable(): Promise<void>;

    /**
     * Adds an IP address to a set.
     * Auto-detects IPv4 vs IPv6 and routes to the correct table/set.
     *
     * @param options - Address, target set, and optional timeout
     * @throws {TypeError} if options are invalid
     * @throws {Error} if IP is invalid or nftables operation fails
     */
    addAddress(options: AddAddressOptions): Promise<void>;

    /**
     * Removes an IP address from a set.
     * Idempotent — no error if IP is not in the set.
     *
     * @param options - Address and target set
     * @throws {TypeError} if options are invalid
     * @throws {Error} if IP is invalid or nftables operation fails
     */
    removeAddress(options: RemoveAddressOptions): Promise<void>;

    /**
     * Adds multiple IP addresses to a set in bulk.
     * Addresses are chunked for efficient netlink communication.
     * Empty arrays are a no-op.
     *
     * @param options - Addresses, target set, and optional timeout
     * @throws {TypeError} if options are invalid
     * @throws {Error} if any IP is invalid or nftables operation fails
     */
    addAddresses(options: AddAddressesOptions): Promise<void>;

    /**
     * Removes multiple IP addresses from a set in bulk.
     * Idempotent — no error if IPs are not in the set.
     * Empty arrays are a no-op.
     *
     * @param options - Addresses and target set
     * @throws {TypeError} if options are invalid
     * @throws {Error} if any IP is invalid or nftables operation fails
     */
    removeAddresses(options: RemoveAddressesOptions): Promise<void>;
}
