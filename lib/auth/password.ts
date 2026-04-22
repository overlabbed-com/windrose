/**
 * Password hashing using bcrypt (pure JavaScript implementation).
 * 
 * Uses bcryptjs which has no native dependencies, making it
 * compatible with all platforms including Docker builds.
 */

import bcrypt from 'bcryptjs';

const SALT_ROUNDS = 12;

/**
 * Hashes a password using bcrypt.
 * 
 * @param password - Plaintext password to hash
 * @returns Promise resolving to the hashed password
 */
export async function hashPassword(password: string): Promise<string> {
  if (!password || password.length === 0) {
    throw new Error('Password cannot be empty');
  }

  const MAX_PASSWORD_LENGTH = 1024;
  if (password.length > MAX_PASSWORD_LENGTH) {
    throw new Error('Password exceeds maximum length');
  }

  try {
    return await bcrypt.hash(password, SALT_ROUNDS);
  } catch (error) {
    console.error('Password hashing failed:', error);
    throw new Error('Password hashing failed');
  }
}

/**
 * Verifies a password against a stored hash.
 * 
 * @param password - Plaintext password to verify
 * @param hash - Stored bcrypt hash
 * @returns Promise resolving to true if password matches
 */
export async function verifyPassword(password: string, hash: string): Promise<boolean> {
  if (!password || !hash) {
    return false;
  }

  try {
    return await bcrypt.compare(password, hash);
  } catch (error) {
    console.error('Password verification error:', error);
    return false;
  }
}

/**
 * Checks if a hash needs rehashing (e.g., if salt rounds increased).
 * 
 * @param hash - Existing hash to check
 * @returns true if the hash should be upgraded
 */
export async function needsRehash(hash: string): Promise<boolean> {
  try {
    // bcrypt hashes include salt rounds in the format $2b$XX$...
    const match = hash.match(/^\$2[aby]\$(\d+)\$/);
    if (!match) return true;
    
    const currentRounds = parseInt(match[1], 10);
    return currentRounds < SALT_ROUNDS;
  } catch {
    return true;
  }
}
