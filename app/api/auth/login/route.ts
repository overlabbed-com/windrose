/**
 * User login endpoint.
 * 
 * POST /api/auth/login
 * Input: { email, password }
 * Output: { token, user: { id, email } }
 * 
 * Looks up user by email, verifies password,
 * and creates a new session.
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { users } from '@/lib/db/schema';
import { verifyPassword } from '@/lib/auth/password';
import { createSession } from '@/lib/auth/session';
import { addJitter } from '@/lib/auth/timing';
import { eq } from 'drizzle-orm';

export async function POST(request: NextRequest): Promise<NextResponse> {
  try {
    // Parse request body
    let body: { email?: string; password?: string };
    try {
      body = await request.json();
    } catch {
      return NextResponse.json(
        { error: 'Invalid request body' },
        { status: 400 }
      );
    }

    const { email, password } = body;

    // Validate email
    if (!email || typeof email !== 'string') {
      return NextResponse.json(
        { error: 'Invalid email address' },
        { status: 400 }
      );
    }

    // Normalize email to lowercase
    const normalizedEmail = email.toLowerCase().trim();

    // Validate password presence
    if (!password || typeof password !== 'string') {
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Look up user by email
    let user: { id: string; email: string; passwordHash: string } | null = null;
    try {
      const result = await db
        .select({
          id: users.id,
          email: users.email,
          passwordHash: users.passwordHash,
        })
        .from(users)
        .where(eq(users.email, normalizedEmail))
        .limit(1);

      if (result.length > 0) {
        user = result[0];
      }
    } catch (error) {
      console.error('User lookup failed:', error instanceof Error ? error.message : 'Unknown error');
      // Add jitter to prevent timing attacks
      await addJitter();
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // If user not found, add jitter and return generic error
    if (!user) {
      await addJitter();
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Verify password
    let isValidPassword = false;
    try {
      isValidPassword = await verifyPassword(password, user.passwordHash);
    } catch (error) {
      console.error('Password verification failed:', error instanceof Error ? error.message : 'Unknown error');
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // If password doesn't match, add jitter and return generic error
    if (!isValidPassword) {
      await addJitter();
      return NextResponse.json(
        { error: 'Invalid credentials' },
        { status: 401 }
      );
    }

    // Extract client metadata for session binding
    const ipAddress = request.headers.get('x-forwarded-for')?.split(',')[0]?.trim() 
      || request.headers.get('x-real-ip') 
      || undefined;
    const userAgent = request.headers.get('user-agent') || undefined;

    // Create session (Redis + PostgreSQL write-through)
    let session: { token: string; userId: string; createdAt: Date; expiresAt: Date; version: number };
    try {
      session = await createSession(user.id, { ipAddress, userAgent });
    } catch (error) {
      console.error('Session creation failed:', error instanceof Error ? error.message : 'Unknown error');
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
      );
    }

    return NextResponse.json({
      token: session.token,
      user: {
        id: user.id,
        email: user.email,
      },
    });

  } catch (error) {
    console.error('Login error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}