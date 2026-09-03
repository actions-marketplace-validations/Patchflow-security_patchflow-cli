# PatchFlow quickstart fixture

These two tiny Python projects are the public, versioned inputs for the
five-minute onboarding and launch demo:

- `vulnerable/app.py` intentionally calls `eval()` and must produce `PY001`.
- `clean/app.py` uses `ast.literal_eval()` and must not produce `PY001`.

They contain no real credentials, packages, or network dependencies. Copy a
fixture outside this repository before scanning it so Git root detection cannot
include the PatchFlow source tree. The automated verification scripts do this
for you.

```bash
./scripts/verify-quickstart.sh "$(command -v patchflow)"
```

On Windows:

```powershell
.\scripts\verify-quickstart.ps1 -Binary (Get-Command patchflow).Source
```
