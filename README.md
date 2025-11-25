# npm-scanner

npm-scanner is a Python script that scans lock/manifest files in the current directory tree for compromised packages.

It uses all files starting with `bom-` (Bill of Materials) as the base to find compromised packages. Each BOM file contains a list of known compromised packages with their versions and associated incident information.

## Features

- Scans multiple lockfile formats: `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `npm-shrinkwrap.json`, etc.
- Supports multiple BOM files for different security incidents
- Generates dependency trees showing how compromised packages are pulled in transitively
- Reports which BOM (incident) each finding is related to
- Runs safely in a sandboxed Docker environment

## Prerequisites

- Docker (recommended and safe approach)
- Python 3.7+ (only for direct execution on already-scanned projects)

## ⚠️ Security Warning

**Do NOT run `npm install`, `yarn install`, or `pnpm install` on your local machine if you suspect the project contains compromised packages.** Malicious code in dependencies can execute during installation and compromise your workstation.

Instead, use the Docker-based workflow below, which runs all package manager operations safely inside an isolated container.

## Usage

### Docker Execution (Recommended - Safe Approach)

This is the **recommended and safe way** to scan projects. All package manager operations happen inside the container, not on your machine.

#### Step 1: Build the Docker Image

```bash
docker build -t npm-scanner .
```

#### Step 2: Run the Scanner

```bash
# Scan a project in the current directory (requires existing lockfiles)
docker run -u $(id -u)  --rm -v $(pwd):/project devopsobj/npm-compromised-package-scanner:latest

# Scan a specific directory (requires existing lockfiles)
docker run -u $(id -u)  --rm -v /path/to/project:/project devopsobj/npm-compromised-package-scanner:latest
```

Make sure to set the user ID of the container to match the user ID of the user running the container. This is to avoid permission issues when scanning the project.

The container's entrypoint script will:
1. Check if lockfiles exist (package-lock.json, yarn.lock, pnpm-lock.yaml)
2. If lockfiles exist: Run the scanner immediately
3. If lockfiles don't exist: Display a security warning and exit

**If you need to generate lockfiles**, you must explicitly opt-in with the `--force-lock-file-generation` flag:

```bash
docker run --rm -v $(pwd):/project npm-scanner --force-lock-file-generation
```

This will:
1. Detect the package manager (npm, yarn, or pnpm)
2. Generate lockfiles **inside the container** (safe, isolated environment)
3. Run the scanner on the generated lockfiles

#### Step 3: Interpret Results

The scanner will:
1. Look for all `bom-*.json` files (in the container)
2. Scan for existing lockfiles in the project
3. Report any compromised packages found with their source BOM and dependency paths

**Why This is Safe:**
- ✅ All operations happen inside the container, isolated from your system
- ✅ No malicious code can execute on your workstation
- ✅ The container has no access to your home directory or sensitive files
- ✅ Container is automatically removed after scanning (`--rm` flag)
- ✅ Package manager operations (if needed) run inside the container, not on your machine

### Explicit Opt-In for Lockfile Generation

The entrypoint script requires explicit user consent before generating lockfiles:

**If lockfiles already exist:**
- Scanner runs immediately

**If lockfiles don't exist:**
- Script displays a security warning
- Exits with instructions to use `--force-lock-file-generation` flag
- Emphasizes the risks of running package managers on potentially compromised projects

**Example output when lockfiles are missing:**
```
=== npm-scanner Entrypoint ===

✓ Found package.json

✗ No lock files found (package-lock.json, yarn.lock, pnpm-lock.yaml)

⚠️  SECURITY WARNING ⚠️

Lock files are required to scan for compromised packages.
However, generating them requires running package manager commands,
which could execute malicious code if the project is compromised.

DO NOT run any package manager (npm, yarn, pnpm) in an environment
that could be compromised or on your local machine.

If you understand the risks and want to generate lock files
inside this isolated container, use:

  docker run --rm -v $(pwd):/project npm-scanner --force-lock-file-generation

This will:
  1. Detect the package manager (npm, yarn, pnpm)
  2. Run 'install' commands ONLY inside this container
  3. Scan the generated lock files

Note: Generation may fail if the project has:
  - Native dependencies (node-gyp, bcrypt, etc.)
  - Private npm registries
  - Git dependencies
  - Workspace monorepos
  - Custom build scripts
```

**With `--force-lock-file-generation` flag:**
- Script detects the package manager (npm, yarn, or pnpm)
- Generates lockfiles inside the container
- Runs the scanner on the generated lockfiles

### Direct Execution (Not Recommended for Untrusted Projects)

```bash
python3 scan_compromised_packages.py
```

Only use this if:
- The project is already known to be safe
- Lockfiles already exist
- You're running on a disposable/isolated machine

The script will:
1. Look for all `bom-*.json` files in the current directory or script directory
2. Scan for lockfiles recursively in the current directory
3. Report any compromised packages found with their source BOM

## BOM File Format

Each BOM file should follow this format:

```json
{
  "name": "Incident Name (e.g., Sha1-Hulud)",
  "date": "YYYY-MM-DD",
  "references": [
    "https://link-to-incident-report.com"
  ],
  "compromised-packages": [
    {"package-name": "1.0.0"},
    {"@scoped/package": "2.3.4"}
  ]
}
```

## Output Example

```
Compromised package found: left-pad:1.0.0
Compromised package found: @asyncapi/diff:0.5.2

Summary:
Unique compromised packages found: 2
Total occurrences across files: 2
Details:
  - left-pad:1.0.0 (BOM: Sha1-Hulud, occurrences: 1)
  - @asyncapi/diff:0.5.2 (BOM: Sha1-Hulud, occurrences: 1)

Dependency paths for compromised package left-pad:1.0.0 (lockfile: ./package-lock.json):
  Path 1:
    my-app:1.0.0
    -> some-library:2.0.0
    -> left-pad:1.0.0

Scanned files:
  - ./package-lock.json
  - ./subdir/package-lock.json
```

## Requirements

- No external Python dependencies (uses only Python standard library)
- Lockfiles must already exist (the scanner does not run `npm install` or similar)

## License

npm-scanner is licensed under the MIT License.

