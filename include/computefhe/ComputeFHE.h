#pragma once

#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

#include <computefhe/ALUOptimized.h>
#include <computefhe/ALUStandard.h>
#include <computefhe/BaseALU.h>
#include <computefhe/BaseALUSimulator.h>
#include <computefhe/CFHETypes.h>
#include <computefhe/ConditionManager.h>
#include <computefhe/Efixedpoint.h>
#include <computefhe/Einteger.h>
#include <computefhe/Evector.h>
#include <computefhe/FixedPoint.h>
#include <computefhe/SimOptimized.h>
#include <computefhe/SimStandard.h>

using namespace lbcrypto;
using namespace std;

namespace computefhe {
    extern ComputeFHE *cfhe_base;
    extern bool CLIENT_MODE;

    /**
     * @brief Initializes the global ComputeFHE environment and cryptographic
     * context.
     *
     * @param cc_param Cryptographic context parameters defining security
     * levels.
     * @param alu_type The ALU implementation to use.
     * @param client_mode Toggles between client and server execution modes.
     * @param simulation_mode Enables or disables simulation mode for testing
     * purposes.
     */
    void Init(CryptoContextParam cc_param = CCPARAM_STD128_3,
              ALUType alu_type = ALU_OPTIMIZED, bool client_mode = false,
              bool simulation_mode = false);

    /**
     * @brief Shuts down the ComputeFHE environment and releases global
     * resources.
     *
     * This should be called at the end of the application lifecycle to ensure
     * that the global singleton is properly destroyed and memory is freed.
     */
    void Finalize();

    /**
     * @class ComputeFHE
     * @brief The core manager class for the ComputeFHE library.
     *
     * This class manages the OpenFHE BinFHEContext, private keys, and the
     * active ALU implementation. It provides the primary API for
     * encrypting/decrypting data and managing the global cryptographic state.
     */
    class ComputeFHE {
      private:
        CryptoContextParam cc_param;
        ALUType alu_type;
        BinFHEContext cc;
        LWEPrivateKey sk;
        BaseALU *alu;
        bool sim_mode;
        bool auto_encrypt_mode;

        void createCC();
        void createALU();

      public:
        /**
         * @brief Constructs a ComputeFHE instance.
         * @param simulation_mode If true, initializes in simulation mode.
         */
        ComputeFHE(bool simulation_mode = false);

        /**
         * @brief Constructs a ComputeFHE instance with specific parameters.
         * @param param The cryptographic context parameters.
         * @param simulation_mode If true, initializes in simulation mode.
         */
        ComputeFHE(CryptoContextParam param, bool simulation_mode = false);

        /**
         * @brief Constructs a ComputeFHE instance with specific parameters and
         * ALU type.
         * @param param The cryptographic context parameters.
         * @param alu_type The ALU implementation to use (Standard or
         * Optimized).
         * @param simulation_mode If true, initializes in simulation mode.
         */
        ComputeFHE(CryptoContextParam param, ALUType alu_type,
                   bool simulation_mode = false);

        /**
         * @brief Constructs a ComputeFHE instance with a specific ALU type.
         * @param alu_type The ALU implementation to use.
         * @param simulation_mode If true, initializes in simulation mode.
         */
        ComputeFHE(ALUType alu_type, bool simulation_mode = false);

        /** @brief Destructor. Cleans up ALU and context resources. */
        ~ComputeFHE();

        /** @brief Returns the underlying OpenFHE BinFHEContext. */
        BinFHEContext &GetBinFHEContext();

        /** @brief Returns the active ALU implementation. */
        BaseALU *GetALU();

        /**
         * @brief Returns the simulator instance. Only valid in simulation mode.
         * Returns nullptr if simulation mode is disabled.
         */
        BaseALUSimulator *GetSimulator();

        /** @brief Returns the current cryptographic context parameters. */
        CryptoContextParam GetCryptoContextParam();

        /** @brief Returns the current ALU type (STANDARD or OPTIMIZED). */
        ALUType GetALUType();

        /** @brief Returns the LWE Private Key. Requires CLIENT_MODE to be true.
         */
        const LWEPrivateKey &GetLWEPrivateKey();

        /** @brief Generates the secret key and switching keys for the context.
         */
        void generateKeys();

        /**
         * @brief Encrypts a 64-bit integer into a FixedPoint bit-vector.
         * @param pt The plaintext integer value.
         * @param n_digits The bit-width of the resulting ciphertext.
         * @param fresh If true, performs fresh encryption; otherwise may use
         * cached logic.
         * @return A FixedPoint object containing encrypted bits.
         */
        FixedPoint EncryptInt(uint64_t pt, size_t n_digits = 8,
                              bool fresh = true);

        /**
         * @brief Decrypts a FixedPoint bit-vector back into a 64-bit integer.
         * @param ct The encrypted bit-vector.
         * @param n_digits The number of bits to decrypt (0 defaults to vector
         * size).
         * @return The decrypted 64-bit unsigned integer.
         */
        uint64_t DecryptInt(const FixedPoint &ct, size_t n_digits = 0);

        /**
         * @brief Encrypts a single boolean value.
         * @param pt The plaintext boolean.
         * @param fresh If true, performs fresh encryption.
         * @return A BinaryDigit proxy acting as a ciphertext.
         */
        BinaryDigit EncryptBool(bool pt, bool fresh = true);

        /**
         * @brief Decrypts a single BinaryDigit bit.
         * @param ct The encrypted bit.
         * @return The decrypted boolean value.
         */
        bool DecryptBool(const BinaryDigit &ct);

        /**
         * @brief Creates an unencrypted FixedPoint representation of an
         * integer.
         *
         * This is used for creating "Constant" operands. These are not
         * cryptographically secure but allow the ALU to perform faster
         * Ciphertext-Plaintext operations.
         *
         * @param pt The plaintext integer.
         * @param n_digits The bit-width.
         * @return A FixedPoint object where is_ct() is false.
         */
        FixedPoint GetConstantInt(uint64_t pt, size_t n_digits = 8);

        /**
         * @brief Converts a constant (unencrypted) FixedPoint back to a 64-bit
         * integer.
         * @param pt The unencrypted bit-vector.
         * @return The resulting 64-bit integer.
         */
        uint64_t ConvertConstantInt(const FixedPoint &pt);

        /**
         * @brief Estimates the noise magnitude within a specific bit.
         * @param ct The ciphertext bit to analyze.
         * @return The noise level (useful for debugging bootstrapping
         * thresholds).
         */
        double extractNoise(ConstLWECiphertext &ct);

        /** @brief Prints the current cryptographic context settings to stdout.
         */
        void PrintCryptoContextParams();

        /** @brief Prints technical details about a specific LWE ciphertext to
         * stdout. */
        void PrintLWECiphertextParams(ConstLWECiphertext &ct);

        /**
         * @brief Checks if Auto-Encrypt mode is enabled.
         */
        bool isAutoEncryptMode();

        /**
         * @brief Sets the Auto-Encrypt mode.
         *
         * When enabled, plaintext literals used in operations with encrypted
         * types are automatically passed through EncryptInt() in client mode.
         * When disabled or in server mode, they are treated as plaintext
         * constants via GetConstantInt().
         *
         * @param mode True to enable automatic encryption of plaintext
         * literals.
         */
        void setAutoEncryptMode(bool mode = true);
    };
} // namespace computefhe
