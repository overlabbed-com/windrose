import { NextRequest, NextResponse } from 'next/server';
import { createSession } from '@/lib/auth/session';
import db from '@/lib/db';
import { users } from '@/lib/db/schema';
import { eq } from 'drizzle-orm';
import { hashPassword } from '@/lib/auth/password';
import { checkRateLimit } from '@/lib/auth/rate-limit';

export async function POST(request: NextRequest) {
  try {
    // Rate limiting: prevent brute force and enumeration attacks
    const clientIP = request.headers.get('x-forwarded-for')?.split(',')[0] || '127.0.0.1';
    const rateLimit = await checkRateLimit(clientIP, 'register');
    
    if (!rateLimit.allowed) {
      return NextResponse.json(
        { error: 'Too many requests. Please try again later.' },
        { status: 429 }
      );
    }

    const body = await request.json() as { email?: string; password?: string };
    const { email, password } = body;

    if (!email || !password) {
      return NextResponse.json({ error: 'Email and password required' }, { status: 400 });
    }

    const existingUser = await db.select().from(users).where(eq(users.email, email)).limit(1);

    if (existingUser.length > 0) {
      // Generic success response to prevent account enumeration
      // Don't reveal whether email exists
      return NextResponse.json({ success: true }, { status: 200 });
    }

    const passwordHash = await hashPassword(password);

    const [newUser] = await db.insert(users).values({ email, passwordHash }).returning();

    // Log registration attempt for security monitoring
    console.log(`New user registered: ${email}`);

    const session = await createSession(newUser.id);

    const response = NextResponse.json({ success: true, sessionToken: session.token });
    response.cookies.set('session', session.token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 60 * 60 * 24 * 7,
      path: '/',
    });

    return response;
  } catch (error) {
    console.error('Registration error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
