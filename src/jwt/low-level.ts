import { SignJWT, jwtVerify, type JWTPayload, type CryptoKey } from 'jose';
import { randomUUID } from 'crypto';

const EDDSA_ALG = 'EdDSA' as const;

export interface SignEdDSAJwtOptions {
     claims: Record<string, unknown>;
     privateKey: CryptoKey | Promise<CryptoKey>;
     ttlSeconds: number;
     jti?: string;
}

export async function signEdDSAJwt(opts: SignEdDSAJwtOptions): Promise<string> {
     const privateKey = await opts.privateKey;

     return new SignJWT(opts.claims)
          .setProtectedHeader({ alg: EDDSA_ALG })
          .setJti(opts.jti ?? randomUUID())
          .setIssuedAt()
          .setExpirationTime(`${opts.ttlSeconds}s`)
          .sign(privateKey);
}

export interface VerifyEdDSAJwtOptions {
     token: string;
     publicKey: CryptoKey | Promise<CryptoKey>;
}

/**
 * Verifies signature and expiry only — pins `algorithms: ['EdDSA']` in code
 * and NEVER reads the algorithm from config or the token's own header, which
 * is the classic algorithm-confusion attack surface. Does not enforce a
 * claim shape beyond what `jose` itself checks (exp); callers are
 * responsible for validating the rest of the payload against their own
 * schema.
 */
export async function verifyEdDSAJwt<T extends JWTPayload = JWTPayload>(opts: VerifyEdDSAJwtOptions): Promise<T> {
     const publicKey = await opts.publicKey;
     const { payload } = await jwtVerify(opts.token, publicKey, { algorithms: [EDDSA_ALG] });
     return payload as T;
}
