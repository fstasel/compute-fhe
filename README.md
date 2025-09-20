# ComputeFHE

ComputeFHE is a C++ project for experimenting with **Fully Homomorphic Encryption over Torus (TFHE)** operations using the [OpenFHE](https://github.com/openfheorg/openfhe-development) library.  
It provides implementations of arithmetic operators, gate logic, and optimized evaluation techniques on encrypted data.

## Features
- Homomorphic arithmetic and logic gate implementations
- Optimized variants for faster evaluation
- Configurable experiments for timing and noise growth analysis
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
