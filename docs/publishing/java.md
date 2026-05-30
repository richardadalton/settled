# Publishing the Java SDK to Maven Central

**Registry:** [Maven Central](https://central.sonatype.com)
**Group ID:** `io.github.richardadalton`
**Artifact ID:** `settled-sdk`
**Current version:** `0.2.0`

---

## One-time setup

### 1. Sonatype account

Sign in at [central.sonatype.com](https://central.sonatype.com) using GitHub. The namespace `io.github.richardadalton` is already verified.

### 2. GPG key

A GPG key is required to sign artifacts. The key with fingerprint `71EF4A51E62B769A027D1C47E05FCDD25B341449` (short ID `5B341449`) is already created and published to `keyserver.ubuntu.com`. If you need to recreate it on a new machine:

```sh
brew install gnupg
gpg --gen-key          # use richard@devjoy.com
gpg --keyserver keyserver.ubuntu.com --send-keys <fingerprint>
```

### 3. Local credentials

Add to `~/.gradle/gradle.properties` (create if absent — never commit this file):

```properties
mavenCentralUsername=<token-username>
mavenCentralPassword=<token-password>
signing.gnupg.keyName=5B341449
signing.gnupg.passphrase=<gpg-passphrase>
```

Generate a new token at **central.sonatype.com → Account → Generate User Token** if needed.

---

## Publishing a new version

### 1. Bump the version

In `sdks/java/build.gradle`:

```groovy
version = '0.2.0'   // update this
```

And in `mavenPublishing`:

```groovy
coordinates('io.github.richardadalton', 'settled-sdk', '0.2.0')
```

### 2. Build and publish

The SDK's Gradle wrapper lives in `demos/java/`. Run from the repo root:

```sh
cd demos/java
./gradlew :java:publishToMavenCentral
```

### 3. Release

Log in to [central.sonatype.com](https://central.sonatype.com), go to **Publish → Deployments**, and confirm the bundle is in **Published** state. Propagation to `repo.maven.apache.org` typically takes 15–30 minutes.

### 4. Verify

```sh
curl -s https://repo.maven.apache.org/maven2/io/github/richardadalton/settled-sdk/0.2.0/settled-sdk-0.2.0.pom | grep version
```

---

## Consumer usage

**Gradle:**
```groovy
implementation 'io.github.richardadalton:settled-sdk:0.2.0'
```

**Maven:**
```xml
<dependency>
  <groupId>io.github.richardadalton</groupId>
  <artifactId>settled-sdk</artifactId>
  <version>0.2.0</version>
</dependency>
```
