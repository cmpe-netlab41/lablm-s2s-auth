import { generateKeyPairSync } from 'crypto';
import { importPKCS8, importSPKI } from 'jose';
import { IssuerKeyRegistry, signS2SToken, verifyS2SToken } from './s2s-token';
import { S2SAuthError } from '../errors';

function generatePemKeyPair() {
     const { publicKey, privateKey } = generateKeyPairSync('ed25519');
     return {
          publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
     };
}

describe('signS2SToken / verifyS2SToken', () => {
     it('round-trips a token signed by a trusted issuer', async () => {
          const { publicKeyPem, privateKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'machine-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(privateKeyPem, 'EdDSA'),
          });

          const claims = await verifyS2SToken({ token, audience: 'machine-service', registry });

          expect(claims.iss).toBe('backend');
          expect(claims.aud).toBe('machine-service');
          expect(claims.jti).toEqual(expect.any(String));
     });

     it('rejects a token from an untrusted issuer', async () => {
          const trusted = generatePemKeyPair();
          const attacker = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem: trusted.publicKeyPem }]);

          const token = await signS2SToken({
               issuer: 'someone-else',
               audience: 'machine-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(attacker.privateKeyPem, 'EdDSA'),
          });

          await expect(verifyS2SToken({ token, audience: 'machine-service', registry })).rejects.toThrow(S2SAuthError);
     });

     it('rejects a token signed for a different audience', async () => {
          const { publicKeyPem, privateKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'some-other-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(privateKeyPem, 'EdDSA'),
          });

          await expect(verifyS2SToken({ token, audience: 'machine-service', registry })).rejects.toThrow();
     });

     it('rejects an expired token', async () => {
          const { publicKeyPem, privateKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'machine-service',
               ttlSeconds: -1,
               privateKey: importPKCS8(privateKeyPem, 'EdDSA'),
          });

          await expect(verifyS2SToken({ token, audience: 'machine-service', registry })).rejects.toThrow();
     });

     it('rejects a tampered signature', async () => {
          const { publicKeyPem, privateKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'machine-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(privateKeyPem, 'EdDSA'),
          });

          const tampered = token.slice(0, -2) + (token.at(-2) === 'A' ? 'B' : 'A') + token.at(-1);

          await expect(verifyS2SToken({ token: tampered, audience: 'machine-service', registry })).rejects.toThrow();
     });
});

describe('IssuerKeyRegistry', () => {
     it('throws on duplicate issuer registration', () => {
          const { publicKeyPem } = generatePemKeyPair();
          expect(
               () =>
                    new IssuerKeyRegistry([
                         { issuer: 'backend', publicKeyPem },
                         { issuer: 'backend', publicKeyPem },
                    ]),
          ).toThrow();
     });

     it('resolves a registered issuer to an importable key', async () => {
          const { publicKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);
          await expect(registry.resolve('backend')).resolves.toBeDefined();
          await expect(importSPKI(publicKeyPem, 'EdDSA')).resolves.toBeDefined();
     });

     it('rejects resolving an unregistered issuer', async () => {
          const registry = new IssuerKeyRegistry([]);
          await expect(registry.resolve('backend')).rejects.toThrow(S2SAuthError);
     });
});
