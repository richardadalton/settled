# Publishing the TypeScript SDK to npm

**Registry:** [npmjs.com](https://www.npmjs.com)
**Package:** `@daltonr/settled-sdk`
**Current version:** `0.1.0`

---

## One-time setup

### 1. npm account

Sign in at [npmjs.com](https://www.npmjs.com). The package is published under the `@daltonr` organisation. Generate an **Automation** token at **Account → Access Tokens → Generate New Token → Automation** and check **Bypass two-factor authentication**.

### 2. npm login

```sh
npm login
```

Or use an automation token (recommended for repeatability):

```sh
npm config set //registry.npmjs.org/:_authToken <token>
```

---

## Publishing a new version

### 1. Bump the version

In `sdks/typescript/package.json`:

```json
"version": "0.2.0"
```

### 2. Build

```sh
cd sdks/typescript
npm install
npm run build
```

This runs `tsc` and syncs the proto file via the `prepack` hook.

### 3. Publish

```sh
npm publish --access public
```

`--access public` is required for scoped packages on the free npm plan.

### 4. Verify

```sh
npm info @daltonr/settled-sdk version
```

---

## Consumer usage

```sh
npm install @daltonr/settled-sdk
```

```typescript
import { SettledClient } from '@daltonr/settled-sdk';
const client = new SettledClient('localhost:50051');
```
