# Repository Guidelines

## Project Structure & Module Organization

mtdd is a Linux C++20 MTProto/FakeTLS proxy. Public interfaces live in
`include/mtdd/`; implementations are in `src/`, grouped into `protocol/`,
`runtime/`, `control/`, and `io/`. `src/main.cpp` starts the executable.
GoogleTest cases are in `tests/unit/`, shared fixtures in `tests/support/`, and
optional smoke tests in `tests/integration/`. `tools/` contains probes,
benchmarks, and build utilities. Design contracts and verification reports are
in `specs/`. Treat `build*/` and `.local-build/` as generated output.

## Build, Test, and Development Commands

Install the Ubuntu dependencies listed in `README.md`, then run:

```sh
cmake -S . -B build -G Ninja -DCMAKE_BUILD_TYPE=Debug
cmake --build build -j2
ctest --test-dir build --output-on-failure
```

These commands configure, build, and run the offline suite. To test a specific
case, use `ctest --test-dir build -R 'MeAudit' --output-on-failure`. Check a
local configuration with `./build/mtdd --config config.local.json --check-config`.
Use a separate sanitizer build with `-DMTDD_SANITIZE=ON`; run its tests with
`ASAN_OPTIONS=detect_leaks=1 UBSAN_OPTIONS=halt_on_error=1`. For a static Linux
binary, see `tools/build-static.sh` and `specs/static-build.md`.

## Coding Style & Testing

Follow the surrounding file's formatting; C++ code generally uses four-space
indentation, `snake_case` functions and variables, and `PascalCase` types. Keep
interfaces in the corresponding public header and implementation details local
to their component. The build enables `-Wall -Wextra -Wpedantic -Wconversion
-Wshadow`; resolve warnings introduced by your changes.

Add focused GoogleTest cases to the relevant `*_test.cpp`, using descriptive
`TEST(Suite, Behavior)` names. Cover failure and lifecycle paths for protocol,
reactor, and resource-management changes. CI builds and tests both normal and
ASan/UBSan configurations. Coverage can be collected with `-DMTDD_COVERAGE=ON`
and `python3 tools/coverage_report.py BUILD_DIRECTORY`; no threshold is enforced
by the project configuration. Live Telegram probes are separate from offline
tests and require an authorized test deployment.

## Changes & Security

This workspace does not include Git history, so no existing commit convention
can be verified. Use concise, descriptive commit subjects. In pull requests,
explain the behavior change, relevant risks, and tests run; link an issue when
available. Never commit credentials, user secrets, API tokens, live traffic, or
local configuration. Keep the management API on a trusted network or secure
tunnel, and use the example configuration only as a template.
