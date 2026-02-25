#!/usr/bin/env node

import { createInterface } from 'node:readline/promises';
import { stdin, stdout } from 'node:process';

const { NftManager } = await import('./lib/index.js');

const rl = createInterface({ input: stdin, output: stdout });

const SETS = ['blacklist', 'droplist'];

let nft = null;

function printMenu() {
  console.log('');
  console.log('  1) Create NftManager');
  console.log('  2) createTable');
  console.log('  3) addAddress');
  console.log('  4) removeAddress');
  console.log('  5) addAddresses');
  console.log('  6) removeAddresses');
  console.log('  7) deleteTable');
  console.log('  0) Exit');
  console.log('');
}

async function prompt(msg) {
  return (await rl.question(msg)).trim();
}

async function askSet() {
  const set = await prompt(`  set (${SETS.join('/')}): `);
  if (!SETS.includes(set)) throw new Error(`Invalid set: ${set}`);
  return set;
}

async function askTimeout() {
  const raw = await prompt('  timeout in seconds (empty = permanent): ');
  if (!raw) return undefined;
  const n = Number(raw);
  if (!Number.isFinite(n) || n <= 0) throw new Error(`Invalid timeout: ${raw}`);
  return n;
}

async function createManager() {
  const tableName = await prompt('  tableName [remnawave]: ') || 'remnawave';
  const blacklistSetName = await prompt('  blacklistSetName [blacklist]: ') || 'blacklist';
  const droplistSetName = await prompt('  droplistSetName [droplist]: ') || 'droplist';
  nft = new NftManager({ tableName, blacklistSetName, droplistSetName });
  console.log(`  -> NftManager created (table=${tableName}, blacklist=${blacklistSetName}, droplist=${droplistSetName})`);
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
          console.log('  -> done');
        });
        break;

      case '3':
        await run(async () => {
          const ip = await prompt('  ip: ');
          const set = await askSet();
          const timeout = await askTimeout();
          await nft.addAddress({ ip, set, timeout });
          console.log(`  -> added ${ip} to ${set}${timeout ? ` (${timeout}s)` : ' (permanent)'}`);
        });
        break;

      case '4':
        await run(async () => {
          const ip = await prompt('  ip: ');
          const set = await askSet();
          await nft.removeAddress({ ip, set });
          console.log(`  -> removed ${ip} from ${set}`);
        });
        break;

      case '5':
        await run(async () => {
          const raw = await prompt('  ips (comma-separated): ');
          const ips = raw.split(',').map(s => s.trim()).filter(Boolean);
          const set = await askSet();
          const timeout = await askTimeout();
          await nft.addAddresses({ ips, set, timeout });
          console.log(`  -> added ${ips.length} address(es) to ${set}`);
        });
        break;

      case '6':
        await run(async () => {
          const raw = await prompt('  ips (comma-separated): ');
          const ips = raw.split(',').map(s => s.trim()).filter(Boolean);
          const set = await askSet();
          await nft.removeAddresses({ ips, set });
          console.log(`  -> removed ${ips.length} address(es) from ${set}`);
        });
        break;

      case '7':
        await run(async () => {
          await nft.deleteTable();
          console.log('  -> done');
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
