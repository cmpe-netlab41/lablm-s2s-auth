import { LazyEdDSAPrivateKey } from '../jwt/keys';
import { signS2SToken } from '../jwt/s2s-token';

export interface CreateS2STokenMinterOptions {
     issuer: string;
     privateKeyPem: string;
     ttlSeconds?: number;
}

const DEFAULT_TTL_SECONDS = 60;

/**
 * Low-level minting seam: produces a function that signs a fresh S2S token
 * for a given audience on demand. Usable anywhere a caller builds its own
 * request headers by hand (see `createS2SAuthStrategy` for the
 * `@lablm/transport`-shaped convenience wrapper).
 */
export function createS2STokenMinter(
     opts: CreateS2STokenMinterOptions,
): (audience: string, claims?: Record<string, unknown>) => Promise<string> {
     const privateKey = new LazyEdDSAPrivateKey(() => opts.privateKeyPem);

     return (audience: string, claims?: Record<string, unknown>) =>
          signS2SToken({
               issuer: opts.issuer,
               audience,
               ttlSeconds: opts.ttlSeconds ?? DEFAULT_TTL_SECONDS,
               claims,
               privateKey: privateKey.get(),
          });
}
