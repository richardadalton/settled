# Publishing the Go SDK

**Registry:** [pkg.go.dev](https://pkg.go.dev) (via GitHub — no account required)
**Module:** `github.com/richardadalton/settled/sdks/go`
**Current version:** `v0.1.0`

Go modules are published by pushing a git tag. There is no separate upload step — the Go module proxy fetches directly from GitHub.

---

## Publishing a new version

### 1. Bump the version

In `sdks/go/go.mod` the module path does not change. The version is carried entirely by the git tag.

If the new version has breaking API changes, increment the major version and add the suffix to the module path:

```
module github.com/richardadalton/settled/sdks/go/v2
```

For non-breaking changes (minor or patch), no file changes are needed.

### 2. Commit and tag

Tags for a module in a subdirectory must be prefixed with the module path:

```sh
git add sdks/go/
git commit -m "feat(sdk-go): release v0.2.0"
git tag sdks/go/v0.2.0
git push origin main
git push origin sdks/go/v0.2.0
```

### 3. Trigger proxy indexing

The Go module proxy caches on first request. Fetch the new version to warm the cache immediately:

```sh
GOPROXY=https://proxy.golang.org GO111MODULE=on \
  go list -m github.com/richardadalton/settled/sdks/go@v0.2.0
```

### 4. Verify

```sh
# Should show the new version
go list -m -versions github.com/richardadalton/settled/sdks/go
```

Or check [pkg.go.dev/github.com/richardadalton/settled/sdks/go](https://pkg.go.dev/github.com/richardadalton/settled/sdks/go) — it indexes automatically within a few minutes of the tag being pushed.

---

## Consumer usage

```sh
go get github.com/richardadalton/settled/sdks/go@v0.1.0
```

```go
import "github.com/richardadalton/settled/sdks/go/client"

c, err := client.New("localhost:50051")
```
