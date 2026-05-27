# Publishing the .NET SDK to NuGet

**Registry:** [nuget.org](https://www.nuget.org)
**Package:** `Settled.Sdk`
**Current version:** `0.1.0`

---

## One-time setup

### 1. NuGet account

Create an account at [nuget.org](https://www.nuget.org). Generate an API key at **Account → API Keys** scoped to the `Settled.Sdk` package with **Push** permission.

### 2. Store the API key

```sh
dotnet nuget add source https://api.nuget.org/v3/index.json \
  --name nuget.org \
  --username richardadalton \
  --password <api-key> \
  --store-password-in-clear-text
```

Or set it as an environment variable for one-off publishes:

```sh
export NUGET_API_KEY=<api-key>
```

---

## Publishing a new version

### 1. Bump the version

In `sdks/dotnet/Settled.Sdk/Settled.Sdk.csproj`:

```xml
<Version>0.2.0</Version>
```

### 2. Pack

```sh
cd sdks/dotnet
dotnet pack Settled.Sdk/Settled.Sdk.csproj --configuration Release
```

This produces `Settled.Sdk/bin/Release/Settled.Sdk.0.2.0.nupkg`.

### 3. Publish

```sh
dotnet nuget push Settled.Sdk/bin/Release/Settled.Sdk.0.2.0.nupkg \
  --api-key $NUGET_API_KEY \
  --source https://api.nuget.org/v3/index.json
```

### 4. Verify

NuGet indexing typically takes a few minutes. Check [nuget.org/packages/Settled.Sdk](https://www.nuget.org/packages/Settled.Sdk) or:

```sh
dotnet package search Settled.Sdk --source https://api.nuget.org/v3/index.json
```

---

## Consumer usage

```sh
dotnet add package Settled.Sdk
```

```csharp
using Settled.Sdk;
using var client = new SettledClient("http://localhost:50051");
```
