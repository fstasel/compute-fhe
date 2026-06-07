# ComputeFHE: Privacy-Preserving General-Purpose Computation Library

ComputeFHE is a high-level C++ library designed for performing efficient arithmetic and logic operations over **Fully Homomorphic Encryption (FHE)**. It serves as a powerful wrapper around the [OpenFHE](https://github.com/openfheorg/openfhe-development) BinFHE backend, implementing specialized gate-level optimizations to reduce bootstrapping requirement.

The library is based on research proposed in:
> **Taşel, F.S., Saran, A.N.** *Improved arithmetic efficiency in TFHE through gate-level optimizations.* J Supercomput 81, 1633 (2025). [https://doi.org/10.1007/s11227-025-08107-8](https://doi.org/10.1007/s11227-025-08107-8)

Please cite the above paper if you use ComputeFHE in your research or commercial projects.

## Features
- **Encrypted Primitives**: Drop-in replacements for standard types (e.g. `Eint8`, `Euint32`, `Ebool`), and for fixed-point real numbers (e.g. `EFix<bits, frac, signed>`).
- **Optimized ALU**: Implements logic optimizations (e.g. MAJ, XOR3 gates and other primitives) to significantly speed up arithmetic.
- **Encrypted Control Flow**: Native `Eif(cond) { ... } else { ... }` macro support for conditional logic on encrypted booleans.
- **Oblivious Memory**: `Evector<T>` container supporting encrypted indexing (accessing an encrypted array without revealing the index).
- **Execution Modes**: Toggle between **Client** (with key management), **Server** (pure homomorphic execution), and **Simulation** (for rapid algorithm prototyping without cryptographic overhead).
- **OpenFHE Integration**: Full support for GINX and LMKCDEY bootstrapping methods.

## Requirements
- **C++17** compatible compiler
- **CMake >= 3.14**
- **OpenFHE v1.2.0+**

### Dependencies (Ubuntu/Debian)
```bash
sudo apt update

# for compiling ComputeFHE
sudo apt install -y build-essential cmake git

# for generating documentation
sudo apt install -y doxygen graphviz

# for formatting source codes
sudo apt install -y clang-format
```

## Building

1. **Install OpenFHE**:
   **Standard Installation:**
   ```bash
   git clone https://github.com/openfheorg/openfhe-development.git
   cd openfhe-development
   mkdir build && cd build
   cmake ..
   make -j$(nproc)
   sudo make install
   ```

   **Recommended for HEXL (Intel Hardware Acceleration) Support:**
   Building with the [OpenFHE Configurator](https://github.com/openfheorg/openfhe-configurator) is recommended for enabling Intel HEXL:
   ```bash
   git clone https://github.com/openfheorg/openfhe-configurator.git
   cd openfhe-configurator

   # (Optional) Tweak the build process using all available cores
   sed -i 's/make -j/make -j$(nproc)/g' scripts/build-openfhe-development.sh

   # Configure installation environment
   export OPENFHE_INSTALL_DIR=/usr/local
   export CMAKE_FLAGS="-DCMAKE_BUILD_TYPE=Release"

   ./scripts/stage-openfhe-development-hexl.sh
   ./scripts/build-openfhe-development.sh
   ```

2. **Build ComputeFHE**:
   ```bash
   git clone https://github.com/fstasel/compute-fhe.git
   cd compute-fhe
   mkdir build && cd build
   cmake ..
   make -j$(nproc)
   
   # Build docs (optional)
   make doc

   # Install library (optional)
   sudo make install
   ```

### Using Docker

Alternatively, you can build and run ComputeFHE using Docker. The provided Dockerfiles automate the process of installing OpenFHE and its dependencies.

**Standard Build:**
```bash
docker build -t computefhe -f docker/compute-fhe/Dockerfile .
```

**Build with Intel HEXL Support:**
```bash
docker build -t computefhe -f docker/compute-fhe-hexl/Dockerfile .
```

**Run the Container:**
```bash
docker run -it computefhe
```

## Quickstart Example

This example demonstrates basic encrypted arithmetic using 32-bit integers.

```cpp
#include <computefhe/ComputeFHE.h>
#include <iostream>

using namespace computefhe;

int main() {
    // Initialize the global context: Toy-security, Optimized ALU, Client Mode
    Init(CCPARAM_TOY, ALU_OPTIMIZED, true);

    // Create encrypted integers (automatic encryption in Client Mode)
    Eint32 a = 42;
    Eint32 b = 15;

    // Perform homomorphic operations
    Eint32 sum = a + b;
    Eint32 prod = a * b;
    
    // Encrypted conditional logic
    Eint32 max;
    Eif(a > b) {
        max = a;
    } else {
        max = b;
    }

    // Decrypt results (Possible only in Client Mode)
    std::cout << "Encrypted Sum: " << (int32_t)sum << std::endl;
    std::cout << "Encrypted Product: " << (int32_t)prod << std::endl;
    std::cout << "Encrypted Max: " << (int32_t)max << std::endl;

    Finalize();
    return 0;
}
```

## Advanced Usage: Oblivious Array Access

ComputeFHE allows you to access array elements using an encrypted index, ensuring that neither the index nor the value retrieved is leaked to the server.

```cpp
Evector<Eint16> encrypted_data = {100, 200, 300, 400};
Eint8 secret_index = 2; // Index is encrypted

Eint16 value = encrypted_data[secret_index]; 
// 'value' now contains an encrypted 300
```

## Integrating ComputeFHE into Your Project
ComputeFHE can be integrated into projects using the CMake build system by adding the following lines to the CMakeLists.txt file of the project:

```cmake
find_package(OpenFHE CONFIG REQUIRED)
find_package(ComputeFHE REQUIRED)

include_directories( ${OpenFHE_INCLUDE} )
include_directories( ${OpenFHE_INCLUDE}/third-party/include )
include_directories( ${OpenFHE_INCLUDE}/core )
include_directories( ${OpenFHE_INCLUDE}/pke )
include_directories( ${OpenFHE_INCLUDE}/binfhe )
link_directories( ${OpenFHE_LIBDIR} )

target_link_libraries(YOUR_PROJECT ComputeFHE::computefhe)
```

## License
This project is licensed under the [MIT License](LICENSE).
