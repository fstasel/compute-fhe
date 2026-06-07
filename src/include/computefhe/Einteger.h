/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file Einteger.h
 * @brief Defines the encrypted integer representation and operations.
 */

#pragma once
#include <computefhe/CFHETypes.h>
#include <computefhe/FixedPoint.h>
#include <iostream>
using namespace std;

namespace computefhe {
    /**
     * @class Einteger
     * @brief Represents an encrypted integer.
     *
     * This class provides a high-level interface for performing arithmetic,
     * logical, and comparison operations on encrypted integer values.
     */
    class Einteger {
      private:
        static bool div_cache(const FixedPoint &a, const FixedPoint &b);
        static bool div_cache(const FixedPoint &a, uint64_t b);
        static bool div_cache(uint64_t a, const FixedPoint &b);

      protected:
        FixedPoint data;
        size_t size;
        bool sign;

        static FixedPoint cached_divident;
        static FixedPoint cached_divisor;
        static FixedPoint cached_quotient;
        static FixedPoint cached_remainder;

        static int64_t sign_extend(uint64_t d, size_t n_digits);
        void _sync_var();
        void _desync_var();
        static bool promote(const Einteger &a, const Einteger &b,
                            FixedPoint &a_out, FixedPoint &b_out);

      public:
        /**
         * @brief Default constructor. Initializes an empty or zero-valued
         * encrypted integer.
         */
        Einteger();

        /**
         * @brief Promotes or truncates an Einteger to a specific bit size.
         * @param a The source integer.
         * @param s The target bit size.
         * @return A FixedPoint representing the promoted/truncated bits.
         */
        static FixedPoint promote(const Einteger &a, size_t s);

        /**
         * @brief Constructs an Einteger from a plaintext `int64_t`.
         * @param d The plaintext integer value.
         */
        Einteger(int64_t d);

        /**
         * @brief Constructs an Einteger with a specified number of bits and
         * signedness.
         * @param n_digits The number of bits for the integer.
         * @param is_signed True if the integer is signed, false otherwise.
         */
        Einteger(size_t n_digits, bool is_signed);

        /**
         * @brief Constructs an Einteger from a plaintext `int64_t` with a
         * specified number of bits.
         * @param d The plaintext integer value.
         * @param n_digits The number of bits for the integer.
         */
        Einteger(int64_t d, size_t n_digits);

        /**
         * @brief Constructs an Einteger from a plaintext `uint64_t` with a
         * specified number of bits.
         * @param d The plaintext unsigned integer value.
         * @param n_digits The number of bits for the integer.
         */
        Einteger(uint64_t d, size_t n_digits);

        /**
         * @brief Constructs an Einteger from an existing `FixedPoint` object.
         * @param fp The `FixedPoint` object representing the encrypted bits.
         * @param is_signed True if the integer is signed, false otherwise.
         */
        Einteger(const FixedPoint &fp, bool is_signed);

        /**
         * @brief Copy constructor.
         * @param other The Einteger object to copy from.
         */
        Einteger(const Einteger &other);

        /**
         * @brief Destructor.
         */
        virtual ~Einteger();

        /**
         * @brief Gets the underlying `FixedPoint` data.
         * @return A constant reference to the `FixedPoint` object.
         */
        const FixedPoint &getData() const;

        /**
         * @brief Gets the number of bits used to represent the encrypted
         * integer.
         * @return The size in bits.
         */
        size_t getSize() const;

        /**
         * @brief Checks if the encrypted integer is signed.
         * @return True if signed, false otherwise.
         */
        bool isSigned() const;

        // Comparison operators
        /**
         * @brief Encrypted equality comparison with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * equal, 0 if not).
         */
        virtual const Einteger operator==(const Einteger &) const;
        /**
         * @brief Encrypted inequality comparison with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * not equal, 0 if equal).
         */
        virtual const Einteger operator!=(const Einteger &) const;
        /**
         * @brief Encrypted greater-than comparison with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * greater, 0 otherwise).
         */
        virtual const Einteger operator>(const Einteger &) const;
        /**
         * @brief Encrypted greater-than-or-equal comparison with another
         * Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * greater or equal, 0 otherwise).
         */
        virtual const Einteger operator>=(const Einteger &) const;
        /**
         * @brief Encrypted less-than comparison with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * less, 0 otherwise).
         */
        virtual const Einteger operator<(const Einteger &) const;
        /**
         * @brief Encrypted less-than-or-equal comparison with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result (1 if
         * less or equal, 0 otherwise).
         */
        virtual const Einteger operator<=(const Einteger &) const;
        /**
         * @brief Encrypted equality comparison with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator==(uint64_t) const;
        /**
         * @brief Encrypted inequality comparison with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator!=(uint64_t) const;
        /**
         * @brief Encrypted greater-than comparison with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator>(uint64_t) const;
        /**
         * @brief Encrypted greater-than-or-equal comparison with a plaintext
         * `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator>=(uint64_t) const;
        /**
         * @brief Encrypted less-than comparison with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator<(uint64_t) const;
        /**
         * @brief Encrypted less-than-or-equal comparison with a plaintext
         * `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator<=(uint64_t) const;

        // Arithmetic operators
        /**
         * @brief Encrypted addition with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the sum.
         */
        virtual const Einteger operator+(const Einteger &) const;
        /**
         * @brief Encrypted addition assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after addition.
         */
        virtual const Einteger operator+=(const Einteger &);
        /**
         * @brief Encrypted subtraction with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the difference.
         */
        virtual const Einteger operator-(const Einteger &) const;
        /**
         * @brief Encrypted subtraction assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after subtraction.
         */
        virtual const Einteger operator-=(const Einteger &);
        /**
         * @brief Encrypted multiplication with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the product.
         */
        virtual const Einteger operator*(const Einteger &) const;
        /**
         * @brief Encrypted multiplication assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after multiplication.
         */
        virtual const Einteger operator*=(const Einteger &);
        /**
         * @brief Encrypted division with another Einteger.
         * @param other The other encrypted integer (divisor).
         * @return A new Einteger representing the quotient.
         */
        virtual const Einteger operator/(const Einteger &) const;
        /**
         * @brief Encrypted division assignment with another Einteger.
         * @param other The other encrypted integer (divisor).
         * @return A reference to this Einteger after division.
         */
        virtual const Einteger operator/=(const Einteger &);
        /**
         * @brief Encrypted modulo with another Einteger.
         * @param other The other encrypted integer (divisor).
         * @return A new Einteger representing the remainder.
         */
        virtual const Einteger operator%(const Einteger &) const;
        /**
         * @brief Encrypted modulo assignment with another Einteger.
         * @param other The other encrypted integer (divisor).
         * @return A reference to this Einteger after modulo.
         */
        virtual const Einteger operator%=(const Einteger &);
        /**
         * @brief Encrypted addition with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the sum.
         */
        virtual const Einteger operator+(uint64_t) const;
        /**
         * @brief Encrypted addition assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after addition.
         */
        virtual const Einteger operator+=(uint64_t);
        /**
         * @brief Encrypted subtraction with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the difference.
         */
        virtual const Einteger operator-(uint64_t) const;
        /**
         * @brief Encrypted subtraction assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after subtraction.
         */
        virtual const Einteger operator-=(uint64_t);
        /**
         * @brief Encrypted multiplication with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the product.
         */
        virtual const Einteger operator*(uint64_t) const;
        /**
         * @brief Encrypted multiplication assignment with a plaintext
         * `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after multiplication.
         */
        virtual const Einteger operator*=(uint64_t);
        /**
         * @brief Encrypted division with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer (divisor).
         * @return A new Einteger representing the quotient.
         */
        virtual const Einteger operator/(uint64_t) const;
        /**
         * @brief Encrypted division assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer (divisor).
         * @return A reference to this Einteger after division.
         */
        virtual const Einteger operator/=(uint64_t);
        /**
         * @brief Encrypted modulo with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer (divisor).
         * @return A new Einteger representing the remainder.
         */
        virtual const Einteger operator%(uint64_t) const;
        /**
         * @brief Encrypted modulo assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer (divisor).
         * @return A reference to this Einteger after modulo.
         */
        virtual const Einteger operator%=(uint64_t);
        /**
         * @brief Encrypted unary negation (two's complement).
         * @return A new Einteger representing the negated value.
         */
        const Einteger operator-() const;

        // Logic operators
        /**
         * @brief Encrypted bitwise AND with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the bitwise AND.
         */
        virtual const Einteger operator&(const Einteger &) const;
        /**
         * @brief Encrypted bitwise AND assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after bitwise AND.
         */
        virtual const Einteger operator&=(const Einteger &);
        /**
         * @brief Encrypted bitwise OR with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the bitwise OR.
         */
        virtual const Einteger operator|(const Einteger &) const;
        /**
         * @brief Encrypted bitwise OR assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after bitwise OR.
         */
        virtual const Einteger operator|=(const Einteger &);
        /**
         * @brief Encrypted bitwise XOR with another Einteger.
         * @param other The other encrypted integer.
         * @return A new Einteger representing the bitwise XOR.
         */
        virtual const Einteger operator^(const Einteger &) const;
        /**
         * @brief Encrypted bitwise XOR assignment with another Einteger.
         * @param other The other encrypted integer.
         * @return A reference to this Einteger after bitwise XOR.
         */
        virtual const Einteger operator^=(const Einteger &);
        /**
         * @brief Encrypted bitwise AND with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the bitwise AND.
         */
        virtual const Einteger operator&(uint64_t) const;
        /**
         * @brief Encrypted bitwise AND assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after bitwise AND.
         */
        virtual const Einteger operator&=(uint64_t);
        /**
         * @brief Encrypted bitwise OR with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the bitwise OR.
         */
        virtual const Einteger operator|(uint64_t) const;
        /**
         * @brief Encrypted bitwise OR assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after bitwise OR.
         */
        virtual const Einteger operator|=(uint64_t);
        /**
         * @brief Encrypted bitwise XOR with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A new Einteger representing the bitwise XOR.
         */
        virtual const Einteger operator^(uint64_t) const;
        /**
         * @brief Encrypted bitwise XOR assignment with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return A reference to this Einteger after bitwise XOR.
         */
        virtual const Einteger operator^=(uint64_t);
        /**
         * @brief Encrypted logical NOT.
         * @return An Einteger representing the encrypted boolean result (1 if
         * zero, 0 if non-zero).
         */
        virtual const Einteger operator!() const;
        /**
         * @brief Encrypted bitwise NOT (one's complement).
         * @return A new Einteger representing the bitwise NOT.
         */
        virtual const Einteger operator~() const;
        /**
         * @brief Encrypted logical AND with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator&&(const Einteger &) const;
        /**
         * @brief Encrypted logical AND with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator&&(uint64_t) const;
        /**
         * @brief Encrypted logical OR with another Einteger.
         * @param other The other encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator||(const Einteger &) const;
        /**
         * @brief Encrypted logical OR with a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        virtual const Einteger operator||(uint64_t) const;

        // TODO: logical and/or for bool-type

        // Increment & Decrement operators
        /**
         * @brief Pre-increment operator. Increments the encrypted integer by
         * one.
         * @return A reference to this Einteger after increment.
         */
        const Einteger operator++();
        /**
         * @brief Post-increment operator. Increments the encrypted integer by
         * one.
         * @return A new Einteger representing the value before increment.
         */
        const Einteger operator++(int);
        /**
         * @brief Pre-decrement operator. Decrements the encrypted integer by
         * one.
         * @return A reference to this Einteger after decrement.
         */
        const Einteger operator--();
        /**
         * @brief Post-decrement operator. Decrements the encrypted integer by
         * one.
         * @return A new Einteger representing the value before decrement.
         */
        const Einteger operator--(int);

        // Shift operators
        /**
         * @brief Encrypted left shift.
         * @param shift The number of positions to shift.
         * @return A new Einteger representing the shifted value.
         */
        const Einteger operator<<(int) const;
        /**
         * @brief Encrypted left shift assignment.
         * @param shift The number of positions to shift.
         * @return A reference to this Einteger after shifting.
         */
        const Einteger operator<<=(int);
        /**
         * @brief Encrypted right shift.
         * @param shift The number of positions to shift.
         * @return A new Einteger representing the shifted value.
         */
        const Einteger operator>>(int) const;
        /**
         * @brief Encrypted right shift assignment.
         * @param shift The number of positions to shift.
         * @return A reference to this Einteger after shifting.
         */
        const Einteger operator>>=(int);

        // Assignment operators
        /**
         * @brief Assignment operator from another Einteger.
         * @param other The Einteger to assign from.
         * @return A reference to this Einteger.
         */
        Einteger &operator=(const Einteger &);
        /**
         * @brief Assignment operator from a plaintext `uint64_t`.
         * @param val The plaintext unsigned integer to assign.
         * @return A reference to this Einteger.
         */
        Einteger &operator=(uint64_t);

        // Type conversion
        /**
         * @brief Explicit conversion to decrypted boolean.
         * @return A decrypted boolean (1 if non-zero, 0 if zero).
         */
        virtual explicit operator bool() const;
        /**
         * @brief Explicit conversion to decrypted `int8_t`.
         * @return A decrypted `int8_t`.
         */
        virtual explicit operator int8_t() const;
        /**
         * @brief Explicit conversion to decrypted `uint8_t`.
         * @return A decrypted `uint8_t`.
         */
        virtual explicit operator uint8_t() const;
        /**
         * @brief Explicit conversion to decrypted `int16_t`.
         * @return A decrypted `int16_t`.
         */
        virtual explicit operator int16_t() const;
        /**
         * @brief Explicit conversion to decrypted `uint16_t`.
         * @return A decrypted `uint16_t`.
         */
        virtual explicit operator uint16_t() const;
        /**
         * @brief Explicit conversion to decrypted `int32_t`.
         * @return A decrypted `int32_t`.
         */
        virtual explicit operator int32_t() const;
        /**
         * @brief Explicit conversion to decrypted `uint32_t`.
         * @return A decrypted `uint32_t`.
         */
        virtual explicit operator uint32_t() const;
        /**
         * @brief Explicit conversion to decrypted `int64_t`.
         * @return A decrypted `int64_t`.
         */
        virtual explicit operator int64_t() const;
        /**
         * @brief Explicit conversion to decrypted `uint64_t`.
         * @return A decrypted `uint64_t`.
         */
        virtual explicit operator uint64_t() const;
        /**
         * @brief Explicit conversion to decrypted `double`.
         * @return A decrypted `double`.
         */
        virtual explicit operator double() const;

        // Friend functions
        /**
         * @brief Overloads the stream insertion operator by decrypting
         * `Einteger`.
         * @param out The output stream.
         * @param obj The Einteger object to print.
         * @return The output stream.
         */
        friend ostream &operator<<(ostream &out, const Einteger &obj);
        /**
         * @brief Friend operator for plaintext `uint64_t` equality comparison
         * with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator==(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` inequality comparison
         * with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator!=(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` greater-than
         * comparison with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator>(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` greater-than-or-equal
         * comparison with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator>=(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` less-than comparison
         * with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator<(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` less-than-or-equal
         * comparison with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator<=(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` addition with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the sum.
         */
        friend const Einteger operator+(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` subtraction with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the difference.
         */
        friend const Einteger operator-(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` multiplication with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the product.
         */
        friend const Einteger operator*(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` division with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the quotient.
         */
        friend const Einteger operator/(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` modulo with Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the remainder.
         */
        friend const Einteger operator%(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` bitwise AND with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the bitwise AND.
         */
        friend const Einteger operator&(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` bitwise OR with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the bitwise OR.
         */
        friend const Einteger operator|(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` bitwise XOR with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return A new Einteger representing the bitwise XOR.
         */
        friend const Einteger operator^(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` logical AND with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator&&(uint64_t a, const Einteger &b);
        /**
         * @brief Friend operator for plaintext `uint64_t` logical OR with
         * Einteger.
         * @param a The plaintext unsigned integer.
         * @param b The encrypted integer.
         * @return An Einteger representing the encrypted boolean result.
         */
        friend const Einteger operator||(uint64_t a, const Einteger &b);

        // TODO: friend shift operators for integral types
        // TODO: friend logical and/or for bool-type
    };

    ostream &operator<<(ostream &out, const Einteger &obj);
    const Einteger operator==(uint64_t a, const Einteger &b);
    const Einteger operator!=(uint64_t a, const Einteger &b);
    const Einteger operator>(uint64_t a, const Einteger &b);
    const Einteger operator>=(uint64_t a, const Einteger &b);
    const Einteger operator<(uint64_t a, const Einteger &b);
    const Einteger operator<=(uint64_t a, const Einteger &b);

    const Einteger operator+(uint64_t a, const Einteger &b);
    const Einteger operator-(uint64_t a, const Einteger &b);
    const Einteger operator*(uint64_t a, const Einteger &b);
    const Einteger operator/(uint64_t a, const Einteger &b);
    const Einteger operator%(uint64_t a, const Einteger &b);

    const Einteger operator&(uint64_t a, const Einteger &b);
    const Einteger operator|(uint64_t a, const Einteger &b);
    const Einteger operator^(uint64_t a, const Einteger &b);
    const Einteger operator&&(uint64_t a, const Einteger &b);
    const Einteger operator||(uint64_t a, const Einteger &b);

    template <typename T, size_t BITS, bool SIGNED>
    /**
     * @brief Template class for fixed-size encrypted integers.
     *
     * This template provides convenient type aliases for common integer sizes
     * (e.g., `Eint8`, `Euint32`). It inherits from `Einteger` and sets the
     * bit size and signedness during construction.
     *
     * @tparam T The underlying plaintext type (e.g., `int8_t`, `uint32_t`).
     * @tparam BITS The number of bits for the encrypted integer.
     * @tparam SIGNED True if the integer is signed, false otherwise.
     */
    class EInt : public Einteger {
      public:
        EInt(T d = 0) : Einteger((uint64_t)d, BITS) { this->sign = SIGNED; }
        EInt(const Einteger &other) : Einteger(promote(other, BITS), SIGNED) {}
    };

    using Ebool = EInt<bool, 1, false>;
    /** @brief Encrypted 8-bit signed integer. */
    using Eint8 = EInt<int8_t, 8, true>;
    /** @brief Encrypted 8-bit unsigned integer. */
    using Euint8 = EInt<uint8_t, 8, false>;
    /** @brief Encrypted 16-bit signed integer. */
    using Eint16 = EInt<int16_t, 16, true>;
    /** @brief Encrypted 16-bit unsigned integer. */
    using Euint16 = EInt<uint16_t, 16, false>;
    /** @brief Encrypted 32-bit signed integer. */
    using Eint32 = EInt<int32_t, 32, true>;
    /** @brief Encrypted 32-bit unsigned integer. */
    using Euint32 = EInt<uint32_t, 32, false>;
    /** @brief Encrypted 64-bit signed integer. */
    using Eint64 = EInt<int64_t, 64, true>;
    /** @brief Encrypted 64-bit unsigned integer. */
    using Euint64 = EInt<uint64_t, 64, false>;
} // namespace computefhe
