/**
 * Native nftables manager for Linux firewall.
 * Manages IPv4/IPv6 tables with dynamic sets via libnftnl + libmnl (direct netlink, no nft CLI).
 * Requires CAP_NET_ADMIN or root privileges.
 */

/** Constructor options. All fields are required — no defaults. */
export interface NftManagerOptions {
    /** Base table name. IPv6 table auto-appends '6'. */
    tableName: string;
    /** Set names. At least 1, no duplicates, non-empty strings. IPv6 sets auto-append '6'. */
    sets: string[];
}

/** Options for adding a single address. */
export interface AddAddressOptions {
    /** IPv4 or IPv6 address (e.g., "1.2.3.4" or "2001:db8::1"). */
    ip: string;
    /** Target set name (must match one from constructor's sets array). */
    set: string;
    /** Timeout in seconds. Omit for permanent ban. */
    timeout?: number;
}

/** Options for removing a single address. */
export interface RemoveAddressOptions {
    /** IPv4 or IPv6 address to remove. */
    ip: string;
    /** Target set name (must match one from constructor's sets array). */
    set: string;
}

/** Options for bulk adding addresses. */
export interface AddAddressesOptions {
    /** Array of IPv4/IPv6 addresses. */
    ips: string[];
    /** Target set name (must match one from constructor's sets array). */
    set: string;
    /** Timeout in seconds. Omit for permanent ban. */
    timeout?: number;
}

/** Options for bulk removing addresses. */
export interface RemoveAddressesOptions {
    /** Array of IPv4/IPv6 addresses to remove. */
    ips: string[];
    /** Target set name (must match one from constructor's sets array). */
    set: string;
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
     * Creates IPv4 and IPv6 tables with all configured sets and filter chains.
     * Idempotent — destroys existing tables first, then recreates.
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
     * Adds an IP address to a set.
     * Auto-detects IPv4 vs IPv6 and routes to the correct table/set.
     *
     * @param options - Address, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if IP is invalid, set name is unknown, or nftables operation fails
     */
    addAddress(options: AddAddressOptions): Promise<void>;

    /**
     * Removes an IP address from a set.
     * Idempotent — no error if IP is not in the set.
     *
     * @param options - Address and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if IP is invalid, set name is unknown, or nftables operation fails
     */
    removeAddress(options: RemoveAddressOptions): Promise<void>;

    /**
     * Adds multiple IP addresses to a set in bulk.
     * Empty arrays are a no-op.
     *
     * @param options - Array of addresses, target set name, and optional timeout.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any IP is invalid, set name is unknown, or nftables operation fails
     */
    addAddresses(options: AddAddressesOptions): Promise<void>;

    /**
     * Removes multiple IP addresses from a set in bulk.
     * Idempotent — no error if IPs are not in the set.
     * Empty arrays are a no-op.
     *
     * @param options - Array of addresses and target set name.
     * @throws {TypeError} if options or fields have wrong types
     * @throws {Error} if any IP is invalid, set name is unknown, or nftables operation fails
     */
    removeAddresses(options: RemoveAddressesOptions): Promise<void>;
}
