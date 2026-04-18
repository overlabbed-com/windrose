/**
 * User logout endpoint.
 * 
 * POST /api/auth/logout
 * Input: session token from x-session-token header
 * Output: { success: true }
 * 
 * Deletes session from both Redis and PostgreSQL.
 */

import { NextRequest, NextResponse } from 'next/server';
import { revokeSession } from '@/lib/auth/session';

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Get session token from header
    const sessionToken = request.headers.get('x-session-token');

    if (!sessionToken) {
      return NextResponse.json(
        { error: 'Session token required' },
        { status: 401 }
      );
    }

    // Revoke session (removes from Redis and PostgreSQL)
    try {
      await revokeSession(sessionToken);
    } catch (error) {
      console.error('Session revocation failed:', error instanceof Error ? error.message : 'Unknown error');
      // Still return success - session might already be invalid
    }

    return NextResponse.json({ success: true });

  } catch (error) {
    console.error('Logout error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}