import jwt from 'jsonwebtoken';
import dotenv from 'dotenv';

dotenv.config();

interface JwtPayload {
  _id: string;
  username: string;
  email: string;
}

// Helper function to verify and decode a JWT
export const authenticateToken = (token: string): JwtPayload | null => {
  const secretKey = process.env.JWT_SECRET_KEY || '';

  try {
    const decoded = jwt.verify(token, secretKey);
    return decoded as JwtPayload;
  } catch (err) {
    console.error('Invalid token:', err.message);
    return null;
  }
};

// Helper function to sign a JWT
export const signToken = (username: string, email: string, _id: string) => {
  const payload = { username, email, _id };
  const secretKey = process.env.JWT_SECRET_KEY || '';

  return jwt.sign(payload, secretKey, { expiresIn: '1h' });
};

// Middleware-like function to attach user to the GraphQL context
export const getUserFromToken = (token: string | undefined): JwtPayload | null => {
  if (!token) {
    return null;
  }

  // Remove "Bearer " prefix if present
  const cleanToken = token.startsWith('Bearer ') ? token.slice(7) : token;
  return authenticateToken(cleanToken);
};