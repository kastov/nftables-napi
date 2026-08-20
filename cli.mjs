#!/usr/bin/env node

import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

const { NftManager } = await import('./lib/index.js');

const rl = createInterface({ input: stdin, output: stdout });

let nft = null;

function printMenu() {
  console.log('');
  console.log('  === Table ===');
  console.log('  1)  Create NftManager');
  console.log('  2)  createTable');
  console.log('  3)  deleteTable');
  console.log('');
  console.log('  === Addresses (ingressAddrSets / egressAddrSets) ===');
  console.log('  4)  addAddress');
  console.log('  5)  removeAddress');
  console.log('  6)  addAddresses');
  console.log('  7)  removeAddresses');
  console.log('');
  console.log('  === Ports (egressPortSets) ===');
  console.log('  8)  addPort');
  console.log('  9)  removePort');
  console.log('  10) addPorts');
  console.log('  11) removePorts');
  console.log('');
  console.log('  0)  Exit');
  console.log('');
}

async function prompt(msg) {
  return (await rl.question(msg)).trim();
}

async function askSet() {
  return await prompt('  set name: ');
}

async function askPortSet() {
  return await prompt('  port set name: ');
}

async function askTimeout() {
  const raw = await prompt('  timeout in seconds (empty = permanent): ');
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid timeout: ${raw}`);
  return n;
}

async function askProtocol() {
  const raw = await prompt('  protocol (tcp / udp / empty = both): ');
  if (!raw) return undefined;
  if (raw !== 'tcp' && raw !== 'udp') throw new Error(`Invalid protocol: ${raw} (expected tcp or udp)`);
  return raw;
}

async function createManager() {
  const tableName = await prompt('  tableName [remnawave]: ') || 'remnawave';

  const setsRaw = await prompt('  ingressAddrSets (comma-separated) [blacklist]: ') || 'blacklist';
  const ingressAddrSets = setsRaw.split(',').map(s => s.trim()).filter(Boolean);

  const egressAddrSetsRaw = await prompt('  egressAddrSets (comma-separated, empty = none): ');
  const egressAddrSets = egressAddrSetsRaw ? egressAddrSetsRaw.split(',').map(s => s.trim()).filter(Boolean) : undefined;

  const egressPortSetsRaw = await prompt('  egressPortSets (comma-separated, empty = none): ');
  const egressPortSets = egressPortSetsRaw ? egressPortSetsRaw.split(',').map(s => s.trim()).filter(Boolean) : undefined;

  const loggingRaw = await prompt('  logging (y/n) [y]: ');
  const logging = !loggingRaw || loggingRaw.toLowerCase().startsWith('y');

  const opts = { tableName, ingressAddrSets, logging };
  if (egressAddrSets) opts.egressAddrSets = egressAddrSets;
  if (egressPortSets) opts.egressPortSets = egressPortSets;

  nft = new NftManager(opts);
  console.log(`  -> NftManager created (table=${tableName}, ingressAddrSets=[${ingressAddrSets}]` +
    (egressAddrSets ? `, egressAddrSets=[${egressAddrSets}]` : '') +
    (egressPortSets ? `, egressPortSets=[${egressPortSets}]` : '') +
    `, logging=${logging})`);
}

async function run(fn) {
  if (!nft) {
    console.log('  [!] Create NftManager first (option 1)');
    return;
  }
  try {
    await fn();
  } catch (err) {
    console.error(`  [ERROR] ${err.message}`);
  }
}

async function main() {
  console.log('nftables-napi interactive CLI');

  while (true) {
    printMenu();
    const choice = await prompt('> ');

    switch (choice) {
      case '1':
        await createManager();
        break;

      case '2':
        await run(async () => {
          await nft.createTable();
          console.log('  -> table created');
        });
        break;

      case '3':
        await run(async () => {
          await nft.deleteTable();
          console.log('  -> table deleted');
        });
        break;

      case '4':
        await run(async () => {
          const ip = await prompt('  ip/cidr: ');
          const set = await askSet();
          const timeout = await askTimeout();
          await nft.addAddress({ ip, set, timeout });
          console.log(`  -> added ${ip} to ${set}${timeout ? ` (${timeout}s)` : ' (permanent)'}`);
        });
        break;

      case '5':
        await run(async () => {
          const ip = await prompt('  ip/cidr: ');
          const set = await askSet();
          await nft.removeAddress({ ip, set });
          console.log(`  -> removed ${ip} from ${set}`);
        });
        break;

      case '6':
        await run(async () => {
          const raw = await prompt('  ips/cidrs (comma-separated): ');
          const ips = raw.split(',').map(s => s.trim()).filter(Boolean);
          const set = await askSet();
          const timeout = await askTimeout();
          await nft.addAddresses({ ips, set, timeout });
          console.log(`  -> added ${ips.length} address(es) to ${set}`);
        });
        break;

      case '7':
        await run(async () => {
          const raw = await prompt('  ips/cidrs (comma-separated): ');
          const ips = raw.split(',').map(s => s.trim()).filter(Boolean);
          const set = await askSet();
          await nft.removeAddresses({ ips, set });
          console.log(`  -> removed ${ips.length} address(es) from ${set}`);
        });
        break;

      case '8':
        await run(async () => {
          const port = Number(await prompt('  port: '));
          const set = await askPortSet();
          const protocol = await askProtocol();
          const timeout = await askTimeout();
          await nft.addPort({ port, set, protocol, timeout });
          console.log(`  -> added port ${port} to ${set} (proto=${protocol || 'both'}${timeout ? `, ${timeout}s` : ', permanent'})`);
        });
        break;

      case '9':
        await run(async () => {
          const port = Number(await prompt('  port: '));
          const set = await askPortSet();
          const protocol = await askProtocol();
          await nft.removePort({ port, set, protocol });
          console.log(`  -> removed port ${port} from ${set} (proto=${protocol || 'both'})`);
        });
        break;

      case '10':
        await run(async () => {
          const raw = await prompt('  ports (comma-separated): ');
          const ports = raw.split(',').map(s => Number(s.trim())).filter(n => !isNaN(n));
          const set = await askPortSet();
          const protocol = await askProtocol();
          const timeout = await askTimeout();
          await nft.addPorts({ ports, set, protocol, timeout });
          console.log(`  -> added ${ports.length} port(s) to ${set}`);
        });
        break;

      case '11':
        await run(async () => {
          const raw = await prompt('  ports (comma-separated): ');
          const ports = raw.split(',').map(s => Number(s.trim())).filter(n => !isNaN(n));
          const set = await askPortSet();
          const protocol = await askProtocol();
          await nft.removePorts({ ports, set, protocol });
          console.log(`  -> removed ${ports.length} port(s) from ${set}`);
        });
        break;

      case '0':
        rl.close();
        return;

      default:
        console.log('  [?] Unknown option');
    }
  }
}

main();
