# ComputeFHE Python

Native Python bindings for [ComputeFHE](https://github.com/fstasel/compute-fhe),
using pybind11 and the upstream OpenFHE backend. Import as `computefhe`.

## Build

Requires Python 3.9+, a C++17 compiler, CMake 3.18+, and installed shared-library
builds of OpenFHE and ComputeFHE. Build and install the C++ library using the
[parent README](../README.md#building) first. Python support is optional; the
normal C++ build does not need Python or pybind11.

From the repository root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install ./python
# For dependencies installed outside the system prefix:
CMAKE_PREFIX_PATH=/path/to/prefix python -m pip install ./python
```

The extension links to the installed libraries. Wheels are local builds and do
not bundle OpenFHE or ComputeFHE; the matching libraries must remain installed.
Development: `python -m pip install -e ./python`. If multiple ComputeFHE installs
exist, select the current checkout's installation with
`-Ccmake.define.ComputeFHE_DIR=/path/to/prefix/lib/cmake/ComputeFHE`.

For a source distribution downloaded separately, run `python -m pip install .`
from the extracted package directory after installing the native dependencies.

The bindings do not patch the C++ library. A clean build with AppleClang 21
currently fails in upstream `Evector.h` because of its `Einteger` to `size_t`
casts. Installing the bindings requires a working native library and headers;
this PR does not resolve that upstream build issue.

## Example

```python
from computefhe import Context, Eint32, select

with Context() as ctx:
    a, b = Eint32(42), Eint32(15)
    total = a + b
    maximum = select(a > b, a, b)
    print(total.decrypt())       # 57
    print(maximum.decrypt())     # 42
```

`Context()` uses real encryption and upstream `STD128_3` parameters. Use
`Context(simulation=True)` for fast plaintext simulation. The simulator still
requires the native libraries. `Parameters.TOY` is for testing, not security.

## API and semantics

- `Ebool`, `Eint8/16/32/64`, `Euint8/16/32/64`, or
  `EncryptedInt(value, bits=32, signed=True)` for widths from 1 through 64.
- Integer `+ - *`, comparisons, `& | ^ ~`, and public-count shifts.
  Results retain the width and wrap modulo `2**bits`.
- `//`, `%`, and `divmod()` are supported only for unsigned integers. Each
  operation calls the existing native `DivU` routine once, which produces both
  quotient and remainder. The wrapper adds no division algorithm or additional
  division optimization. Signed division raises `NotImplementedError`, even
  for positive signed values. `/` is deliberately undefined for integers.
- `EncryptedFixed(value, bits=32, frac=16, signed=True)` supports `+ - *`,
  negation, and comparisons. Inputs truncate toward zero at `2**-frac`.
  Multiplication preserves upstream behavior: it drops low operand bits before
  multiplying, so precision can be lower than rounding an exact product.
  Fixed-point division is not exposed in this initial version.
- Mixed encrypted operands require matching width, signedness, and fractional
  width. `integer.cast(bits=16, signed=True)` explicitly converts integers.
  Arithmetic results are `EncryptedInt`/`EncryptedFixed`, not alias subclasses.
- Plain Python operands are **public constants**, checked against the operand's
  range. Constructors encrypt by default; `encrypted=False` creates a public
  constant explicitly. Out-of-range inputs raise `OverflowError`.
- `.decrypt()` is the only public plaintext conversion. `bool()`, `int()`,
  `float()`, Python `if`, `and`, `or`, and chained comparisons cannot implicitly
  decrypt. Comparisons return encrypted one-bit integers. Use `&`, `|`, `~`
  for encrypted boolean logic.
- `select(condition, a, b)` calls the upstream multiplexer. At least one branch
  must be encrypted. Both branches are evaluated before the call.
- `EncryptedVector([Eint8(10), Eint8(20)])[Euint8(1)]` performs an oblivious
  read through the existing C++ `Evector`/`Eitem` API. Writes also delegate to
  native `Eitem`; no selection loop is implemented in Python. Upstream keeps
  only the lowest `ceil(log2(length))` index bits (at least one), zero-extending
  shorter indices. For length 3, encrypted index 4 therefore selects element 0;
  index 3 reads zero and writes nothing. Supply valid encrypted indices when
  aliasing is unwanted. Plain indices follow Python indexing. Vectors must be
  nonempty and homogeneous.
- Unsigned division by a public zero raises `ZeroDivisionError`. An encrypted divisor
  must be nonzero: the wrapper does not decrypt it to check. Use an encrypted
  comparison and `select()` to substitute a nonzero divisor when needed.
- There is one active context per process, restricted to the creating thread.
  Nested contexts, use after close, and reuse after `fork()` are rejected.
  The bindings retain the GIL. Use independent processes for concurrency.

Initial scope is local client computation and simulation. Server key exchange,
ciphertext serialization, the C++ `Eif` macro, and the full low-level ALU API
are not exposed. Python cannot overload `if`; use `select()`.

## Test

```sh
python -m unittest discover -s python/tests -v
COMPUTEFHE_TEST_CRYPTO=1 python -m unittest discover -s python/tests -v
python python/examples/quickstart.py --simulation
```

The default suite uses the actual native simulator. The optional crypto test
uses upstream TOY parameters for a real encryption/evaluation/decryption check.

The GitHub Actions Python workflow attempts to build the checked-out C++ library
and run these tests on Linux and macOS. Native build failures also fail the job;
the macOS upstream build limitation above remains unresolved. See
[development notes](CONTRIBUTING.md) for local build and test details.
Please retain the research citations in the
[parent README](../README.md#computefhe-privacy-preserving-general-purpose-computation-library)
when using ComputeFHE in research. Licensed under MIT.
