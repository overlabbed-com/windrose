/**
 * User registration endpoint.
 * 
 * POST /api/auth/register
 * Input: { email, password }
 * Output: { token, user: { id, email } }
 * 
 * Creates a new user with hashed password, default organization,
 * and session token.
 */

import { NextRequest, NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { users, organizations, userOrganizations } from '@/lib/db/schema';
import { hashPassword } from '@/lib/auth/password';
import { createSession } from '@/lib/auth/session';
import { addJitter } from '@/lib/auth/timing';
import { eq } from 'drizzle-orm';

/**
 * Email validation regex.
 * Allows standard email formats, case-insensitive.
 */
const EMAIL_REGEX = /^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$/;

/**
 * Validates email format.
 */
function isValidEmail(email: string): boolean {
  return EMAIL_REGEX.test(email) && email.length <= 255;
}

/**
 * Validates password strength.
 * Minimum 8 characters required.
 */
function isValidPassword(password: string): boolean {
  return password.length >= 8 && password.length <= 1024;
}

/**
 * Generates a slug from email address.
 * Takes the local part before @ and appends a random suffix.
 */
function generateSlug(email: string): string {
  const localPart = email.split('@')[0].toLowerCase().replace(/[^a-z0-9]/g, '');
  const suffix = Math.random().toString(36).substring(2, 8);
  return `${localPart}-${suffix}`;
}

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

    if (!isValidEmail(normalizedEmail)) {
      return NextResponse.json(
        { error: 'Invalid email address' },
        { status: 400 }
      );
    }

    // Validate password
    if (!password || typeof password !== 'string') {
      return NextResponse.json(
        { error: 'Password must be at least 8 characters' },
        { status: 400 }
      );
    }

    if (!isValidPassword(password)) {
      return NextResponse.json(
        { error: 'Password must be at least 8 characters' },
        { status: 400 }
      );
    }

    // Check if user already exists
    const existingUsers = await db
      .select({ id: users.id })
      .from(users)
      .where(eq(users.email, normalizedEmail))
      .limit(1);

    if (existingUsers.length > 0) {
      // Add jitter to prevent timing attacks
      await addJitter();
      return NextResponse.json(
        { error: 'An account with this email already exists' },
        { status: 409 }
      );
    }

    // Hash password
    let passwordHash: string;
    try {
      passwordHash = await hashPassword(password);
    } catch (error) {
      console.error('Password hashing failed:', error instanceof Error ? error.message : 'Unknown error');
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
      );
    }

    // Create user in PostgreSQL
    let userId: string;
    try {
      const result = await db.insert(users).values({
        email: normalizedEmail,
        passwordHash,
      }).returning({ id: users.id });

      userId = result[0].id;
    } catch (error) {
      console.error('User creation failed:', error instanceof Error ? error.message : 'Unknown error');
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
      );
    }

    // Create default organization for user
    const orgSlug = generateSlug(normalizedEmail);
    let orgId: string;
    try {
      const orgResult = await db.insert(organizations).values({
        name: normalizedEmail,
        slug: orgSlug,
      }).returning({ id: organizations.id });

      orgId = orgResult[0].id;
    } catch (error) {
      console.error('Organization creation failed:', error instanceof Error ? error.message : 'Unknown error');
      // Rollback user creation
      await db.delete(users).where(eq(users.id, userId));
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
      );
    }

    // Add user to organization as owner
    try {
      await db.insert(userOrganizations).values({
        userId,
        organizationId: orgId,
        role: 'owner',
      });
    } catch (error) {
      console.error('Organization membership creation failed:', error instanceof Error ? error.message : 'Unknown error');
      // Rollback org and user creation
      await db.delete(organizations).where(eq(organizations.id, orgId));
      await db.delete(users).where(eq(users.id, userId));
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
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
      session = await createSession(userId, { ipAddress, userAgent });
    } catch (error) {
      console.error('Session creation failed:', error instanceof Error ? error.message : 'Unknown error');
      // Rollback org and user creation
      await db.delete(userOrganizations).where(eq(userOrganizations.userId, userId));
      await db.delete(organizations).where(eq(organizations.id, orgId));
      await db.delete(users).where(eq(users.id, userId));
      return NextResponse.json(
        { error: 'Authentication service unavailable' },
        { status: 503 }
      );
    }

    return NextResponse.json({
      token: session.token,
      user: {
        id: userId,
        email: normalizedEmail,
      },
    }, { status: 201 });

  } catch (error) {
    console.error('Registration error:', error instanceof Error ? error.message : 'Unknown error');
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}