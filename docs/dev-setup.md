# Developer Setup

This note is for contributors working in a fresh local environment. It keeps the setup small and mirrors the repository's existing CMake and CTest flow.

## Required Tools

- CMake 3.21 or newer for the shared presets in `CMakePresets.json`
- CMake 3.20 or newer for the manual fallback flow
- A C++20 compiler
  - Windows: Visual Studio 2022 or Build Tools 2022 with the MSVC v143 toolset
  - Linux: `g++` 10+ or `clang++` 14+ plus `make` or `ninja`
- Git for normal contribution flow

## Quick Start With Presets

`CMakePresets.json` includes two repeatable local entry points:

- `dev-debug`: default local iteration build with tests enabled
- `ci-release`: release build intended to mirror the GitHub Actions CI flags

Local debug iteration:

```bash
cmake --preset dev-debug
cmake --build --preset dev-debug
ctest --preset dev-debug
```

Local CI-style validation:

```bash
cmake --preset ci-release
cmake --build --preset ci-release
ctest --preset ci-release
```

## Manual Fallback

If you do not want to use presets, or if your local CMake is 3.20 but not 3.21+, the equivalent manual flow is:

```bash
cmake -S . -B build -D CMAKE_BUILD_TYPE=Debug -D BUILD_TESTING=ON
cmake --build build
ctest --test-dir build --output-on-failure
```

## Windows Notes

- Run from a Developer PowerShell for Visual Studio 2022, an x64 Native Tools prompt, or another shell where the MSVC toolchain is already available.
- If `cmake` is missing from `PATH`, install either the Visual Studio C++ workload with CMake support or a standalone Kitware CMake package, then reopen the shell.
- Visual Studio generators are multi-config, so the presets set `Debug` or `Release` again at build and test time for consistency.

## Linux Notes

- A small Ubuntu/Debian-style setup is usually enough:

```bash
sudo apt install cmake g++ make
```

- If you prefer Clang, configure manually with `-D CMAKE_CXX_COMPILER=clang++` or create a local user preset.

## Expected Local Outputs

- Build directories under `build/dev-debug` or `build/ci-release`
- Test runs for `parser`, `detector`, and `cli`
- `compile_commands.json` in the debug build directory when the selected generator supports it
