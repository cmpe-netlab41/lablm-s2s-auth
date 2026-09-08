import { SignJWT, decodeJwt, jwtVerify, type CryptoKey } from 'jose';
import { randomUUID } from 'crypto';
import { z, type ZodTypeAny } from 'zod';
import { LazyEdDSAPublicKey } from './keys';
import { S2SAuthError } from '../errors';

const EDDSA_ALG = 'EdDSA' as const;

export const S2SBaseClaimsSchema = z.object({
     iss: z.string().min(1),
     aud: z.string().min(1),
     jti: z.string().min(1),
     exp: z.number(),
     iat: z.number().optional(),
});
export type S2SBaseClaims = z.infer<typeof S2SBaseClaimsSchema>;

export interface TrustedIssuer {
     issuer: string;
     publicKeyPem: string;
}

/**
 * Multi-issuer public-key lookup. Adding a new trusted caller is one more
 * entry in this list, not a code change.
 */
export class IssuerKeyRegistry {
     private readonly keys = new Map<string, LazyEdDSAPublicKey>();

     constructor(trustedIssuers: TrustedIssuer[]) {
          for (const trusted of trustedIssuers) {
               if (this.keys.has(trusted.issuer)) {
                    throw new Error(`Duplicate trusted issuer: ${trusted.issuer}`);
               }
               this.keys.set(trusted.issuer, new LazyEdDSAPublicKey(() => trusted.publicKeyPem));
          }
     }

     async resolve(issuer: string): Promise<CryptoKey> {
          const key = this.keys.get(issuer);
          if (!key) throw new S2SAuthError('UNTRUSTED_ISSUER', `Untrusted S2S issuer: ${issuer}`);
          return key.get();
     }
}

export interface SignS2STokenOptions {
     issuer: string;
     audience: string;
     ttlSeconds: number;
     claims?: Record<string, unknown>;
     privateKey: CryptoKey | Promise<CryptoKey>;
     jti?: string;
}

export async function signS2SToken(opts: SignS2STokenOptions): Promise<string> {
     const privateKey = await opts.privateKey;

     return new SignJWT({ ...opts.claims, iss: opts.issuer, aud: opts.audience })
          .setProtectedHeader({ alg: EDDSA_ALG })
          .setJti(opts.jti ?? randomUUID())
          .setIssuedAt()
          .setExpirationTime(`${opts.ttlSeconds}s`)
          .sign(privateKey);
}

export interface VerifyS2STokenOptions {
     token: string;
     audience: string;
     registry: IssuerKeyRegistry;
     schema?: ZodTypeAny;
}

/**
 * Verifies a generic multi-issuer S2S token. The unverified `iss` claim is
 * peeked at only to pick which registered public key to attempt — that peek
 * grants no trust by itself. Trust is established by `jwtVerify`'s signature
 * check plus its own `issuer`/`audience` equality checks against the value
 * we just looked up the key by, so an attacker cannot claim a trusted `iss`
 * without holding that issuer's private key.
 */
export async function verifyS2SToken<T extends S2SBaseClaims = S2SBaseClaims>(
     opts: VerifyS2STokenOptions,
): Promise<T> {
     const { iss } = decodeJwt(opts.token);
     if (!iss) throw new S2SAuthError('INVALID_TOKEN', 'Token is missing an iss claim');

     const publicKey = await opts.registry.resolve(iss);

     const { payload } = await jwtVerify(opts.token, publicKey, {
          algorithms: [EDDSA_ALG],
          issuer: iss,
          audience: opts.audience,
     });

     return (opts.schema ?? S2SBaseClaimsSchema).parse(payload) as T;
}
