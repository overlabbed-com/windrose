import { NextResponse } from 'next/server';

/**
 * Health check endpoint for deployment.
 * Returns 200 if the service is healthy.
 */
export async function GET() {
  return NextResponse.json(
    {
      status: 'healthy',
      timestamp: new Date().toISOString(),
    },
    { status: 200 }
  );
}