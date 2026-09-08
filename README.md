# @lablm/s2s-auth

Generic, robust service-to-service (S2S) authentication framework using EdDSA (Ed25519) JSON Web Tokens (JWT) for the LabLM ecosystem.

Supports standalone Node.js clients and first-class NestJS guard/module integration.

## Installation

```bash
# npm
npm install @lablm/s2s-auth

# pnpm
pnpm add @lablm/s2s-auth
```

## Features

- 🔐 **EdDSA (Ed25519) Cryptography:** Fast, modern asymmetric signatures via `jose`.
- 🛡️ **Replay Attack Protection:** Nonce/JTI tracking with TTL store (in-memory or Redis).
- ⏱️ **Clock Skew Tolerance:** Tolerates slight server time drifts safely.
- 🦅 **NestJS Module & Guard:** Plug-and-play `@S2SAuthGuard()` and `@S2SAuthExempt()` decorator.
- 🌐 **Zero Monorepo Lock-in:** 100% self-contained, typed, and works in any Node.js service.

## Quick Start (NestJS)

### 1. Register Module in Server

```typescript
import { Module } from '@nestjs/common';
import { S2SAuthModule } from '@lablm/s2s-auth/nest';

@Module({
  imports: [
    S2SAuthModule.register({
      trustedPublicKeys: [process.env.S2S_PUBLIC_KEY!],
      expectedAudience: 'backend',
    }),
  ],
})
export class AppModule {}
```

### 2. Protect Controllers / Routes

```typescript
import { Controller, Get, UseGuards } from '@nestjs/common';
import { S2SAuthGuard, S2SAuthExempt } from '@lablm/s2s-auth/nest';

@Controller('internal')
@UseGuards(S2SAuthGuard)
export class InternalController {
  @Get('secure-data')
  getSecureData() {
    return { status: 'authorized' };
  }

  @Get('health')
  @S2SAuthExempt()
  healthCheck() {
    return { status: 'ok' };
  }
}
```

### 3. Mint Tokens in Client Service

```typescript
import { createS2STokenMinter } from '@lablm/s2s-auth';

const minter = createS2STokenMinter({
  issuer: 'machine-service',
  audience: 'backend',
  privateKeyPem: process.env.S2S_PRIVATE_KEY!,
  ttlSeconds: 60,
});

const token = await minter.mintToken();
// Send in request header: Authorization: Bearer <token>
```

## Scripts

```bash
pnpm run build     # Compile TypeScript to dist/
pnpm run typecheck # Run TypeScript checks
pnpm run test      # Run Jest unit test suite
```

## License

[Apache-2.0](LICENSE)
