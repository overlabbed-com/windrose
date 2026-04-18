import { NextRequest, NextResponse } from 'next/server';
import { getUserOrganizations, getDefaultOrganization } from '@/lib/auth/session';
import { verifySession } from '@/lib/auth/verify';

// Extend NextRequest with user context
declare global {
  namespace NextRequest {
    interface Headers {
      get(name: 'x-session-token'): string | null;
    }
  }
}

export interface AuthContext {
  userId: string;
  organizations: {
    organizationId: string;
    name: string;
    slug: string;
    logoUrl: string | null;
    role: string;
    joinedAt: Date;
    permissions: string[];
  }[];
  activeOrg: {
    organizationId: string;
    userId: string;
    role: string;
    permissions: string[];
  } | null;
}

/**
 * Auth middleware for Next.js API routes
 * Verifies session token and loads organization memberships
 */
export async function authMiddleware(
  request: NextRequest
): Promise<{
  success: boolean;
  auth?: AuthContext;
  error?: NextResponse;
}> {
  // Get session token from header (not user-supplied x-user-id)
  const sessionToken = request.headers.get('x-session-token');

  if (!sessionToken) {
    return {
      success: false,
      error: NextResponse.json({ error: 'Unauthorized', code: 'MISSING_SESSION_TOKEN' }, { status: 401 })
    };
  }

  // Verify session token - this prevents x-user-id header spoofing
  const userId = await verifySession(sessionToken);

  if (!userId) {
    return {
      success: false,
      error: NextResponse.json({ error: 'Unauthorized', code: 'INVALID_SESSION' }, { status: 401 })
    };
  }

  try {
    // Load user's organization memberships
    const organizations = await getUserOrganizations(userId);

    // Set default org if only one membership
    let activeOrg = null;
    if (organizations.length === 1) {
      activeOrg = {
        organizationId: organizations[0].organizationId,
        userId,
        role: organizations[0].role,
        permissions: organizations[0].permissions
      };
    }

    const auth: AuthContext = {
      userId,
      organizations,
      activeOrg
    };

    return { success: true, auth };
  } catch (error) {
    console.error('Auth middleware error:', error);
    return {
      success: false,
      error: NextResponse.json({ error: 'Internal server error' }, { status: 500 })
    };
  }
}

/**
 * Create response with auth headers
 * Returns available organizations in response headers
 */
export function withAuthHeaders(
  response: NextResponse,
  auth: AuthContext
): NextResponse {
  // Add user ID header
  response.headers.set('x-user-id', auth.userId);

  // Add organization count
  response.headers.set('x-org-count', auth.organizations.length.toString());

  // Add available org IDs as comma-separated header
  if (auth.organizations.length > 0) {
    response.headers.set(
      'x-org-ids',
      auth.organizations.map(o => o.organizationId).join(',')
    );

    // Add default org if set
    if (auth.activeOrg) {
      response.headers.set('x-active-org', auth.activeOrg.organizationId);
    }
  }

  return response;
}

/**
 * Require authentication middleware wrapper
 * Use at the start of API route handlers
 */
export function requireAuth(
  handler: (request: NextRequest, auth: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const { success, auth, error } = await authMiddleware(request);

    if (!success || !auth) {
      return error!;
    }

    return handler(request, auth);
  };
}

/**
 * Require specific organization context
 * Returns 403 if not in org context
 */
export function requireOrgContext(
  handler: (request: NextRequest, auth: AuthContext) => Promise<NextResponse>
) {
  return async (request: NextRequest): Promise<NextResponse> => {
    const { success, auth, error } = await authMiddleware(request);

    if (!success || !auth) {
      return error!;
    }

    if (!auth.activeOrg) {
      return NextResponse.json(
        {
          error: 'Organization context required',
          code: 'ORG_REQUIRED',
          availableOrgs: auth.organizations.map(o => ({
            id: o.organizationId,
            name: o.name,
            slug: o.slug
          }))
        },
        { status: 403 }
      );
    }

    return handler(request, auth);
  };
}