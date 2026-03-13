# Coverage Auto-Researcher Runbook

This document is a systematic methodology for an autonomous agent to iteratively
improve test coverage in the ATI codebase. Each loop iteration is self-contained,
measurable, and produces a concrete coverage improvement.

## Prerequisites

```bash
cargo llvm-cov --version   # LLVM-based line/region coverage
cargo nextest --version     # Fast parallel test runner
cargo mutants --version     # Mutation testing
```

## The Loop

```
1. MEASURE  ──→  cargo llvm-cov --json
                  Parse JSON, identify lowest-coverage files

2. DIAGNOSE ──→  cargo mutants --file <worst_file>
                  Find missed mutations (tests pass with broken code)

3. FIX      ──→  Write tests targeting gaps
                  Use tests/common/ helpers, follow existing patterns

4. VERIFY   ──→  cargo test && cargo llvm-cov --json
                  Confirm tests pass, confirm coverage improved

5. COMMIT   ──→  git add + commit
                  "test: improve coverage for <module>"

         └──→  Loop back to step 1
```

## Step 1: Measure Coverage

### Terminal summary
```bash
cargo llvm-cov --summary-only
```

### Machine-readable JSON
```bash
cargo llvm-cov --json --output-path coverage/current.json 2>/dev/null
```

### HTML report (per-file, per-line highlighting)
```bash
cargo llvm-cov --html --output-dir coverage/
```

### LCOV format (for CI upload)
```bash
cargo llvm-cov --lcov --output-path coverage/lcov.info
```

### Using nextest (faster parallel execution)
```bash
cargo llvm-cov nextest --html --output-dir coverage/
```

### Coverage for a specific test file only
```bash
cargo llvm-cov --test http_test --json 2>/dev/null
```

### Extract worst files (lowest coverage %)
```bash
cargo llvm-cov --json 2>/dev/null | jq -r '
  .data[0].files
  | sort_by(.summary.lines.percent)
  | .[:10]
  | .[] | "\(.summary.lines.percent)% \(.filename)"
'
```

## Step 2: Diagnose with Mutation Testing

Mutation testing finds test quality gaps that line coverage misses. A function can
be 100% "covered" but if no test asserts its return value, a mutation (changing the
return) won't be caught.

### List all possible mutations (dry run)
```bash
cargo mutants --list 2>&1 | head -50
```

### Run mutations on a single file (fast iteration)
```bash
cargo mutants --file src/core/http.rs --timeout 60
```

### Run mutations matching a function name
```bash
cargo mutants --re "function_name" --timeout 60
```

### Run all mutations (slow — hours for full codebase)
```bash
cargo mutants --timeout 120 --jobs 4
```

### Interpret results
- **Caught**: Test failed when mutation injected — good, test is effective
- **Missed**: Tests still pass with mutation — **test gap, needs fixing**
- **Unviable**: Mutation doesn't compile — ignore
- **Timeout**: Mutation causes hang — investigate

### Parse mutation results
```bash
# Missed mutations (the gaps to fix)
cat mutants.out/missed.txt

# Group missed mutations by file
sort mutants.out/missed.txt | cut -d: -f1 | uniq -c | sort -rn
```

## Step 3: Prioritize & Fix

### Priority order
1. **Lowest coverage % files first** (from llvm-cov JSON)
2. **Most missed mutations** (from cargo mutants)
3. **Largest uncovered files** (high line count + low coverage = biggest win)
4. Skip files < 20 lines (diminishing returns)
5. Skip `src/main.rs` and `src/cli/mod.rs` (thin dispatch, hard to unit test)

### Test writing rules
1. **Always use `tests/common/mod.rs` helpers** — `test_provider()`, `test_tool()`, `test_keyring()`, etc.
2. **Follow existing patterns** — look at the closest existing test file for the module
3. **Integration tests** go in `tests/<module>_test.rs`, **unit tests** go inline with `#[cfg(test)]`
4. **Use wiremock** for anything touching HTTP
5. **Use tempfile::TempDir** for anything touching the filesystem
6. **Run `cargo test` after each change** — never commit broken tests
7. **Run `cargo clippy --tests`** — no warnings allowed
8. **One test file per commit** — keep commits atomic

## Step 4: Verify

```bash
# All tests pass
cargo test

# No clippy warnings
cargo clippy --tests

# Formatting clean
cargo fmt --check

# Coverage improved (compare to baseline)
cargo llvm-cov --json --output-path coverage/after.json 2>/dev/null
```

### Compare before/after
```bash
# Quick diff using jq
diff <(jq '.data[0].totals.lines' coverage/baseline.json) \
     <(jq '.data[0].totals.lines' coverage/after.json)
```

## Step 5: Commit

```bash
git add tests/<module>_test.rs
git commit -m "test: improve coverage for <module>"
```

Then loop back to step 1.

## JSON Output Structure Reference

The `cargo llvm-cov --json` output:
```json
{
  "data": [{
    "totals": {
      "lines": {"count": N, "covered": M, "percent": P},
      "regions": {"count": N, "covered": M, "notcovered": X, "percent": P},
      "functions": {"count": N, "covered": M, "percent": P}
    },
    "files": [{
      "filename": "src/core/http.rs",
      "summary": {
        "lines": {"count": 200, "covered": 150, "percent": 75.0},
        "regions": {...},
        "functions": {...}
      }
    }]
  }]
}
```

## Commands Cheat Sheet

```bash
# Full coverage report (JSON for parsing)
cargo llvm-cov --json --output-path coverage/current.json 2>/dev/null

# Quick summary (terminal)
cargo llvm-cov --summary-only

# HTML report
cargo llvm-cov --html --output-dir coverage/

# Find 10 worst files
cargo llvm-cov --json 2>/dev/null | jq -r '.data[0].files | sort_by(.summary.lines.percent) | .[:10] | .[] | "\(.summary.lines.percent)% \(.filename)"'

# Mutation test single file
cargo mutants --file src/core/http.rs --timeout 60

# Mutation test single function
cargo mutants --re "function_name" --timeout 60

# Fast test run (nextest)
cargo nextest run

# Run specific test
cargo nextest run test_name_here

# Check everything passes
cargo test && cargo clippy --tests && cargo fmt --check

# CI coverage threshold check (fail if below 75%)
cargo llvm-cov --fail-under-lines 75
```
