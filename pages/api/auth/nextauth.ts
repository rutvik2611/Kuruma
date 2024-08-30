import NextAuth, { DefaultSession, User } from 'next-auth';
import { JWT } from 'next-auth/jwt';
import CredentialsProvider from 'next-auth/providers/credentials';
import { PrismaClient } from '@prisma/client';
import bcrypt from 'bcrypt';

const prisma = new PrismaClient();

// Extend the built-in session types
interface ExtendedSession extends DefaultSession {
  user: {
    id: string;
    level: number;
    isAdmin: boolean;
  } & DefaultSession['user']
}

// Extend the built-in user types
interface ExtendedUser extends User {
  level: number;
  isAdmin: boolean;
}

// Extend the built-in JWT types
interface ExtendedJWT extends JWT {
  id: string;
  level: number;
  isAdmin: boolean;
}

export default NextAuth({
  providers: [
    CredentialsProvider({
      name: 'Credentials',
      credentials: {
        email: { label: "Email", type: "text" },
        password: { label: "Password", type: "password" }
      },
      async authorize(credentials) {
        if (!credentials?.email || !credentials?.password) {
          return null;
        }

        const user = await prisma.user.findUnique({
          where: { email: credentials.email }
        });

        if (!user) {
          return null;
        }

        const isPasswordValid = await bcrypt.compare(credentials.password, user.password);

        if (!isPasswordValid) {
          return null;
        }

        return {
          id: user.id.toString(),
          email: user.email,
          name: user.name,
          level: user.level,
          isAdmin: user.isAdmin,
        } as ExtendedUser;
      }
    })
  ],
  callbacks: {
    async jwt({ token, user }) {
      if (user) {
        return {
          ...token,
          id: user.id,
          level: (user as ExtendedUser).level,
          isAdmin: (user as ExtendedUser).isAdmin,
        };
      }
      return token;
    },
    async session({ session, token }) {
      return {
        ...session,
        user: {
          ...session.user,
          id: token.id as string,
          level: token.level as number,
          isAdmin: token.isAdmin as boolean,
        },
      } as ExtendedSession;
    }
  },
  pages: {
    signIn: '/auth/signin',
  },
});
