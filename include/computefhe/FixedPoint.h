/**
 * @file FixedPoint.h
 * @brief Defines the fundamental bit-level and bit-vector data structures for
 * FHE operations.
 */

#pragma once
#include <openfhe/binfhe/binfhecontext.h>
#include <vector>

using namespace lbcrypto;
using namespace std;

#define COPY_CT(x) std::make_shared<LWECiphertextImpl>(*x)

namespace computefhe {

    /**
     * @struct BinaryDigit
     * @brief A proxy-object representing a single bit that can behave as either
     * a ciphertext or a plaintext.
     *
     * This struct facilitates transparent handling of bits within the library
     * by wrapping OpenFHE's LWE types. It tracks whether the data is encrypted
     * via the `is_ct` flag, allowing ALU operations to choose the appropriate
     * cryptographic kernels.
     */
    struct BinaryDigit {
        static uint
            new_id;      ///< Global static counter used to assign unique IDs.
        uint id = 0;     ///< Unique identifier for this bit instance.
        LWECiphertext c; ///< The underlying LWE ciphertext bit.
        LWEPlaintext p;  ///< The underlying LWE plaintext bit.
        bool is_ct; ///< True if the object is currently acting as a ciphertext.

        /** @brief Default constructor. */
        BinaryDigit();
        /** @brief Copy constructor. */
        BinaryDigit(const BinaryDigit &other);
        /** @brief Constructs a proxy from a constant ciphertext reference. */
        BinaryDigit(ConstLWECiphertext &ct);
        /** @brief Constructs a proxy from a ciphertext object. */
        BinaryDigit(const LWECiphertext &ct);
        /** @brief Constructs a proxy from a plaintext bit. */
        BinaryDigit(LWEPlaintext pt);
        /** @brief Constructs a proxy with specific ciphertext and plaintext
         * values. */
        BinaryDigit(const ConstLWECiphertext &ct, LWEPlaintext pt,
                    bool is_ct = false);

        /** @brief Assignment from another BinaryDigit proxy. */
        BinaryDigit &operator=(const BinaryDigit &other);
        /** @brief Assigns a ciphertext bit to the proxy and sets is_ct to true.
         */
        BinaryDigit &operator=(const LWECiphertext &other);
        /** @brief Assigns a plaintext bit to the proxy and sets is_ct to false.
         */
        BinaryDigit &operator=(LWEPlaintext pt);

        /** @brief Compares two proxy bits for equality. */
        bool operator==(const BinaryDigit &other) const;
        /** @brief Compares two proxy bits for inequality. */
        bool operator!=(const BinaryDigit &other) const;

        /** @brief Conversion operator to a mutable LWECiphertext reference. */
        operator LWECiphertext &();
        /** @brief Conversion operator to a constant LWECiphertext reference. */
        operator const LWECiphertext &() const;
        /** @brief Conversion operator to a ConstLWECiphertext wrapper. */
        operator ConstLWECiphertext() const;
        /** @brief Conversion operator to LWEPlaintext. */
        operator LWEPlaintext() const;
    };

    /**
     * @struct FixedPoint
     * @brief A bit-vector representation of an encrypted or plaintext word.
     *
     * Inherits from `std::vector<BinaryDigit>`. This class represents multi-bit
     * data (such as integers or fixed-point values) where each index
     * corresponds to a single bit position. It is the primary data structure
     * consumed by the BaseALU.
     */
    struct FixedPoint : public vector<BinaryDigit> {
        /** @brief Default constructor. */
        FixedPoint();
        /** @brief Constructs a bit-vector of size n. */
        FixedPoint(size_t n);
        /** @brief Constructs a bit-vector from a range of BinaryDigit proxies.
         */
        FixedPoint(vector<BinaryDigit>::const_iterator begin,
                   vector<BinaryDigit>::const_iterator end);
        /** @brief Constructs a bit-vector from an initializer list of bits. */
        FixedPoint(std::initializer_list<BinaryDigit> list);
        /** @brief Constructs from an existing vector of BinaryDigit proxies. */
        FixedPoint(const vector<BinaryDigit> &other);
        /** @brief Constructs from a vector of LWE ciphertexts. */
        FixedPoint(const vector<LWECiphertext> &other);
        /** @brief Constructs from a vector of plaintext bits. */
        FixedPoint(const vector<LWEPlaintext> &other);

        /**
         * @brief Determines if the bit-vector represents encrypted data.
         * @return True if all bits in the vector are ciphertexts.
         */
        bool is_ct() const;
    };
} // namespace computefhe