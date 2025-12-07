# ComputeFHE

ComputeFHE is a C++ project for arithmetic operations over **Fully Homomorphic Encryption over Torus (TFHE)** using the [OpenFHE](https://github.com/openfheorg/openfhe-development) library based on algorithms proposed in:

> Taşel, F.S., Saran, A.N. Improved arithmetic efficiency in TFHE through gate-level optimizations. J Supercomput 81, 1633 (2025). https://doi.org/10.1007/s11227-025-08107-8

It provides implementations of standard and optimized arithmetic operators and gate logic operations on encrypted data.

Please cite the paper if you use ComputeFHE in your research.


## Features
- Homomorphic arithmetic and logic gate implementations
- Optimized variants for faster computation
- Clean CMake-based build system

## Requirements
- **C++17** compiler (e.g., `g++ >= 9` or `clang >= 10`)
- **CMake >= 3.14**
- **OpenFHE** library (installed on your system)

## Building

1. Clone this repository:
   ```bash
   git clone https://github.com/fstasel/compute-fhe.git
   cd compute-fhe
   ```

2. Make sure you have OpenFHE installed. If not:
   ```bash
   git clone https://github.com/openfheorg/openfhe-development.git
   cd openfhe-development
   mkdir build && cd build
   cmake .. -DCMAKE_INSTALL_PREFIX=/usr/local
   make -j$(nproc)
   sudo make install
   ```

3. Build ComputeFHE:
   ```bash
   cd compute-fhe
   mkdir build && cd build
   cmake ..
   make -j$(nproc)
   ```

4. Run the program:
   ```bash
   ./compute-fhe
   ```

## License
This project is licensed under the [MIT License](LICENSE).
