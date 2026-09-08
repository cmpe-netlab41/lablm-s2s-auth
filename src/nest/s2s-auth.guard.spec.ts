import { jest } from '@jest/globals';
import { HttpException } from '@nestjs/common';
import { Reflector } from '@nestjs/core';
import { generateKeyPairSync } from 'crypto';
import { importPKCS8 } from 'jose';
import { S2SAuthGuard } from './s2s-auth.guard';
import { S2SReplayProtectionService } from './s2s-replay-protection.service';
import { IssuerKeyRegistry, signS2SToken } from '../jwt/s2s-token';

function generatePemKeyPair() {
     const { publicKey, privateKey } = generateKeyPairSync('ed25519');
     return {
          publicKeyPem: publicKey.export({ type: 'spki', format: 'pem' }).toString(),
          privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
     };
}

function buildContext(headers: Record<string, string>, handlerMetadata: string | undefined = undefined) {
     const request = { headers };
     return {
          switchToHttp: () => ({ getRequest: () => request }),
          getHandler: () => ({}),
          getClass: () => ({}),
          __handlerMetadata: handlerMetadata,
          request,
     } as any;
}

describe('S2SAuthGuard', () => {
     function makeGuard(registry: IssuerKeyRegistry, exemptReason: string | undefined = undefined) {
          const reflector = { getAllAndOverride: jest.fn().mockReturnValue(exemptReason) } as unknown as Reflector;
          const replayProtection = new S2SReplayProtectionService();
          const guard = new S2SAuthGuard(reflector, { audience: 'machine-service', registry }, replayProtection);
          return guard;
     }

     it('rejects a request with no Authorization header', async () => {
          const registry = new IssuerKeyRegistry([]);
          const guard = makeGuard(registry);
          const ctx = buildContext({});

          await expect(guard.canActivate(ctx)).rejects.toThrow(HttpException);
          await expect(guard.canActivate(ctx)).rejects.toMatchObject({ message: 'S2S_TOKEN_MISSING' });
     });

     it('allows a valid token from a trusted issuer through, and rejects replay', async () => {
          const { publicKeyPem, privateKeyPem } = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([{ issuer: 'backend', publicKeyPem }]);
          const guard = makeGuard(registry);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'machine-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(privateKeyPem, 'EdDSA'),
          });
          const ctx = buildContext({ authorization: `Bearer ${token}` });

          await expect(guard.canActivate(ctx)).resolves.toBe(true);
          expect(ctx.request.s2sToken.iss).toBe('backend');

          await expect(guard.canActivate(ctx)).rejects.toMatchObject({ message: 'S2S_TOKEN_REPLAYED' });
     });

     it('bypasses verification entirely when the route is marked exempt', async () => {
          const registry = new IssuerKeyRegistry([]);
          const guard = makeGuard(registry, 'intentionally public');
          const ctx = buildContext({});

          await expect(guard.canActivate(ctx)).resolves.toBe(true);
     });

     it('rejects a token from an untrusted issuer with a generic invalid error', async () => {
          const attacker = generatePemKeyPair();
          const registry = new IssuerKeyRegistry([]); // nobody trusted
          const guard = makeGuard(registry);

          const token = await signS2SToken({
               issuer: 'backend',
               audience: 'machine-service',
               ttlSeconds: 60,
               privateKey: importPKCS8(attacker.privateKeyPem, 'EdDSA'),
          });
          const ctx = buildContext({ authorization: `Bearer ${token}` });

          await expect(guard.canActivate(ctx)).rejects.toMatchObject({ message: 'S2S_TOKEN_INVALID' });
     });
});
