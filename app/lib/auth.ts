import db from "@repo/db/client";
import CredentialsProvider from "next-auth/providers/credentials"
import bcrypt from "bcrypt";
import { z } from "zod";

const credentialsSchema = z.object({
    phone: z.string().min(10, "Phone number must be at least 10 digits").max(15, "Phone number is too long"),
    password: z.string().min(8, "Password must be at least 8 characters long")
  });
// type Credentials = z.infer<typeof credentialsSchema>;

export const authOptions = {
    providers: [
      CredentialsProvider({
          name: 'Credentials',
          credentials: {
            phone: { label: "Phone number", type: "text", placeholder: "1231231231" },
            password: { label: "Password", type: "password" }
          },
          // TODO: User credentials type from next-auth
          async authorize(credentials:any) {
            // zod validation done, do OTP validation here

            const parsedCredentials = credentialsSchema.safeParse(credentials);
            if (!parsedCredentials.success) {
                throw new Error("Invalid input");
              }
            
            const { phone, password } = parsedCredentials.data;

            const hashedPassword = await bcrypt.hash(password, 10);
            const existingUser = await db.user.findFirst({
                where: {
                    number: phone
                }
            });

            if (existingUser) {
                const passwordValidation = await bcrypt.compare(hashedPassword, existingUser.password);
                if (passwordValidation) {
                    return {
                        id: existingUser.id.toString(),
                        name: existingUser.name,
                        email: existingUser.number
                    }
                }
                return null;
            }

            try {
                const user = await db.user.create({
                    data: {
                        number: phone,
                        password: hashedPassword
                    }
                });
            
                return {
                    id: user.id.toString(),
                    name: user.name,
                    email: user.number
                }
            } catch(e) {
                console.error(e);
            }

            return null
          },
        })
    ],
    secret: process.env.JWT_SECRET || "secret",
    callbacks: {
        // TODO: can u fix the type here? Using any is bad
        async session({ token, session }: any) {
            session.user.id = token.sub

            return session
        }
    }
  }
 