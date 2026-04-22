import { NextRequest, NextResponse } from 'next/server';
import { revokeSession } from '@/lib/auth/session';

export async function POST(request: NextRequest) {
  try {
    const sessionToken = request.cookies.get('session')?.value || request.headers.get('x-session-token');

    if (!sessionToken) {
      return NextResponse.json({ error: 'Session token required' }, { status: 401 });
    }

    try {
      await revokeSession(sessionToken);
    } catch (error) {
      console.error('Session revocation failed:', error);
    }

    const response = NextResponse.json({ success: true });
    response.cookies.set('session', '', { httpOnly: true, secure: process.env.NODE_ENV === 'production', sameSite: 'lax', maxAge: 0, path: '/' });

    return response;
  } catch (error) {
    console.error('Logout error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
