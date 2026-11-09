# Developing the Python bindings

The package is a separate CMake project so Python dependencies remain optional
for C++ consumers. Install OpenFHE and this checkout's ComputeFHE shared library
first, then use `pip install -e ./python` from the repository root. CMake locates
the libraries through their installed package configuration files.

For a non-system installation:

```sh
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_PREFIX_PATH=/path/to/prefix -DCMAKE_INSTALL_PREFIX=/path/to/prefix
CPATH=/path/to/prefix/include cmake --build build --target computefhe -j 4
cmake --install build
CMAKE_PREFIX_PATH=/path/to/prefix python -m pip install -e ./python
COMPUTEFHE_TEST_CRYPTO=1 python -m unittest discover -s python/tests -v
python python/examples/quickstart.py --simulation
```

Rebuild and reinstall the extension after changing C++ bindings. To test source
and wheel packaging, install `build` and run `python -m build python`.

The suite uses the actual native simulator, including exhaustive four-bit
arithmetic on both ALUs. Set `COMPUTEFHE_TEST_CRYPTO=1` to include real TOY
cryptography tests for arithmetic, unsigned division, selection, vectors, and
fixed-point operations. TOY parameters are only appropriate for tests.

Keep decryption explicit and preserve context ownership checks. The backend's
single global context requires operations to run in the creating thread; the
bindings retain the GIL. Tests must not replace native FHE with a Python mock.

Initial scope covers local client and simulator contexts. Server key exchange,
ciphertext serialization, signed division, fixed-point division, and the complete
low-level ALU API are not exposed. The wrapper delegates unsigned division to
native `DivU`, vectors to `Evector`/`Eitem`, and shifts to native operators.
Do not implement missing core algorithms or modify core sources in this PR.
Python handles type conversion, argument validation, and context ownership.

Local validation of the vector correction passed 17 tests, including real TOY
encryption, against the previously installed library and headers that contained
earlier portability fixes. Those fixes have been reverted from the PR. This
result is not evidence that unmodified upstream builds on macOS: a separate
AppleClang 21 build fails on the existing `Evector.h` casts. CI must build the
checked-out core without patches and report any upstream build failures.
