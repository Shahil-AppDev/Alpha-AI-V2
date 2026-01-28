import jwt from 'jsonwebtoken';
import { NextRequest, NextResponse } from 'next/server';

const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'AlphaAI2026!Secure';
const ADMIN_EMAIL = process.env.ADMIN_EMAIL || 'admin@alpha-ai.com';
const JWT_SECRET = process.env.JWT_SECRET || 'your-super-secret-jwt-key-change-this-in-production-2026';

export async function POST(request: NextRequest) {
  try {
    const { email, password } = await request.json();

    // Validate credentials (accept both email and username)
    if ((email === ADMIN_EMAIL || email === ADMIN_USERNAME) && password === ADMIN_PASSWORD) {
      // Generate JWT token
      const token = jwt.sign(
        {
          username: ADMIN_USERNAME,
          email: ADMIN_EMAIL,
          role: 'admin',
        },
        JWT_SECRET,
        { expiresIn: '24h' }
      );

      return NextResponse.json({
        success: true,
        token,
        user: {
          id: ADMIN_USERNAME,
          name: ADMIN_USERNAME,
          email: ADMIN_EMAIL,
          role: 'admin',
          permissions: ['*'],
        },
      });
    } else {
      return NextResponse.json(
        { success: false, message: 'Identifiants incorrects' },
        { status: 401 }
      );
    }
  } catch (error) {
    return NextResponse.json(
      { success: false, message: 'Erreur serveur' },
      { status: 500 }
    );
  }
}
