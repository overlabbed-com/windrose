/**
 * Unified session creation for all authentication methods.
 */

import { createHmac } from 'crypto';

export { createSession, verifySession, revokeSession, revokeAllSessions, getSessionVersion } from './verify';
export type { SessionData } from './redis';

// Session affinity secret - use a default for dev, require in production
const SESSION_AFFINITY_SECRET = process.env.SESSION_AFFINITY_SECRET || 'dev-secret-change-in-production';

/**
 * Gets the session affinity key.
 * Used by load balancer to route same session to same replica.
 * 
 * @param sessionToken - Session token
 * @returns Affinity key (64 characters, full HMAC-SHA256)
 */
export function getSessionAffinityKey(sessionToken: string): string {
  const hash = createHmac('sha256', SESSION_AFFINITY_SECRET)
    .update(sessionToken)
    .digest('hex');
  return hash;
}

// Stub for getUserOrganizations
export const getUserOrganizations = async (userId: string) => { return []; };
