---
name: Project language is Rust
description: All implementation code for the settled project must be in Rust, not Python or other languages
type: feedback
---

The core product must be built in Rust. Python scripts and tests are acceptable for tooling (e.g. test vector generators, cross-validation scripts) when Python is the better fit.

**Why:** User clarified after initial correction — Python is fine for peripheral tooling, not for the core library/server/SDKs.

**How to apply:** settled-core, settled-server, and all SDK code = Rust. Generator scripts, cross-language test harnesses, CI utilities = Python or Rust, whichever is cleaner.
