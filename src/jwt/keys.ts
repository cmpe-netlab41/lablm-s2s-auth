import { importPKCS8, importSPKI, type CryptoKey } from 'jose';

const EDDSA_ALG = 'EdDSA' as const;

/**
 * Parses a PEM key once and reuses it. jose's import functions are async and
 * PEM parsing is not free — doing it per request would be wasted work.
 */
export class LazyEdDSAPublicKey {
     private keyPromise?: Promise<CryptoKey>;

     constructor(private readonly getPem: () => string | undefined) {}

     get(): Promise<CryptoKey> {
          if (!this.keyPromise) {
               const pem = this.getPem();
               if (!pem) throw new Error('EdDSA public key is not configured');
               this.keyPromise = importSPKI(pem, EDDSA_ALG);
          }
          return this.keyPromise;
     }
}

export class LazyEdDSAPrivateKey {
     private keyPromise?: Promise<CryptoKey>;

     constructor(private readonly getPem: () => string | undefined) {}

     get(): Promise<CryptoKey> {
          if (!this.keyPromise) {
               const pem = this.getPem();
               if (!pem) throw new Error('EdDSA private key is not configured');
               this.keyPromise = importPKCS8(pem, EDDSA_ALG);
          }
          return this.keyPromise;
     }
}
