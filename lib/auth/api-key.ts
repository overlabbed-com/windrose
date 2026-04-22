/**
 * API Key management using bcrypt for secure hashing.
 */

import bcrypt from 'bcryptjs';
import { randomBytes } from 'crypto';

const SALT_ROUNDS = 12;
const PREFIX_LENGTH = 8;

/**
 * Generates a new API key.
 * Returns both the plain key (for display) and the hash (for storage).
 * 
 * @returns Object with plain key, hash, and prefix
 */
export async function generateApiKey(): Promise<{
  plainKey: string;
  hash: string;
  prefix: string;
}> {
  const plainKey = randomBytes(32).toString('hex');
  const hash = await bcrypt.hash(plainKey, SALT_ROUNDS);
  const prefix = plainKey.substring(0, PREFIX_LENGTH);
  
  return { plainKey, hash, prefix };
}

/**
 * Verifies an API key against a stored hash.
 * Uses constant-time comparison via bcrypt.compare.
 * 
 * @param plainKey - Plain API key to verify
 * @param hash - Stored hash
 * @returns true if key matches
 */
export async function verifyApiKey(plainKey: string, hash: string): Promise<boolean> {
  if (!plainKey || !hash) return false;
  
  try {
    return await bcrypt.compare(plainKey, hash);
  } catch {
    return false;
  }
}

/**
 * Checks if a hash needs rehashing.
 * 
 * @param hash - Existing hash to check
 * @returns true if the hash should be upgraded
 */
export async function needsRehash(hash: string): Promise<boolean> {
  try {
    const match = hash.match(/^\$2[aby]\$(\d+)\$/);
    if (!match) return true;
    
    const currentRounds = parseInt(match[1], 10);
    return currentRounds < SALT_ROUNDS;
  } catch {
    return true;
  }
}
