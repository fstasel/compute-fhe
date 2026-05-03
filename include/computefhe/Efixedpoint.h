/**
 * @file Efixedpoint.h
 * @brief Defines the encrypted fixed-point number representation and
 * operations.
 */

#pragma once

#include <computefhe/Einteger.h>

namespace computefhe {
    /**
     * @class Efixedpoint
     * @brief Represents an encrypted fixed-point number.
     *
     * Inherits from Einteger and uses a scaling factor (2^frac_size) to
     * represent fractional values. This class allows for high-level arithmetic
     * and comparison on encrypted real numbers, supporting both signed and
     * unsigned logic.
     */
    class Efixedpoint : public Einteger {
      protected:
        size_t frac_size;

        static FixedPoint double2fp(double d, size_t n_digits, size_t n_frac);
        static void promote(const Efixedpoint &a, const Efixedpoint &b,
                            FixedPoint &a_out, FixedPoint &b_out,
                            size_t &n_digits_out, size_t &n_frac_out,
                            bool &sign_out);
        static FixedPoint promote(const Efixedpoint &a, size_t n_digits,
                                  size_t n_frac);

      public:
        /**
         * @brief Default constructor. Initializes a "zero" encrypted
         * fixed-point value.
         */
        Efixedpoint();

        /**
         * @brief Constructs a "zero" Efixedpoint with specific bitsize.
         * @param n_digits Total number of bits (integer + fractional).
         * @param n_frac Number of bits reserved for the fractional part.
         * @param is_signed Whether to treat the value as a signed two's
         * complement number.
         */
        Efixedpoint(size_t n_digits, size_t n_frac, bool is_signed);

        /**
         * @brief Constructs and encrypts a plaintext double.
         * @param d The plaintext value to encrypt.
         * @param n_digits Total bit width.
         * @param n_frac Fractional bit width.
         * @param is_signed Signedness of the encrypted representation.
         */
        Efixedpoint(double d, size_t n_digits, size_t n_frac, bool is_signed);

        /**
         * @brief Wraps an existing FixedPoint bit-vector as a fixed-point
         * number.
         * @param fp The underlying encrypted bit-vector.
         * @param n_frac Fractional bit width.
         * @param is_signed Signedness.
         */
        Efixedpoint(const FixedPoint &fp, size_t n_frac, bool is_signed);

        /**
         * @brief Copy constructor.
         */
        Efixedpoint(const Efixedpoint &other);

        /**
         * @brief Conversion constructor from an Einteger.
         * The resulting fixed-point number will have a fractional part of 0
         * bits.
         */
        Efixedpoint(const Einteger &other);

        /**
         * @brief Gets the number of bits used for the fractional part.
         * @return fractional bit count.
         */
        size_t getFracSize() const;

        /**
         * @brief Manually adjusts the fractional size metadata.
         * @note This does not perform bit-shifting; use operator<< or
         * operator>> for scaling.
         * @param n New fractional bit count.
         */
        void setFracSize(size_t);

        // Comparison operators
        using Einteger::operator==;
        using Einteger::operator!=;
        using Einteger::operator>;
        using Einteger::operator>=;
        using Einteger::operator<;
        using Einteger::operator<=;

        /** @brief Encrypted equality comparison (ciphertext-ciphertext). */
        virtual const Einteger operator==(const Efixedpoint &) const;
        /** @brief Encrypted inequality comparison (ciphertext-ciphertext). */
        virtual const Einteger operator!=(const Efixedpoint &) const;
        /** @brief Encrypted greater-than comparison (ciphertext-ciphertext). */
        virtual const Einteger operator>(const Efixedpoint &) const;
        /** @brief Encrypted greater-than-or-equal comparison
         * (ciphertext-ciphertext). */
        virtual const Einteger operator>=(const Efixedpoint &) const;
        /** @brief Encrypted less-than comparison (ciphertext-ciphertext). */
        virtual const Einteger operator<(const Efixedpoint &) const;
        /** @brief Encrypted less-than-or-equal comparison
         * (ciphertext-ciphertext). */
        virtual const Einteger operator<=(const Efixedpoint &) const;

        /** @brief Encrypted equality comparison with plaintext double. */
        virtual const Einteger operator==(double) const;
        /** @brief Encrypted inequality comparison with plaintext double. */
        virtual const Einteger operator!=(double) const;
        /** @brief Encrypted greater-than comparison with plaintext double. */
        virtual const Einteger operator>(double) const;
        /** @brief Encrypted greater-than-or-equal comparison with plaintext
         * double. */
        virtual const Einteger operator>=(double) const;
        /** @brief Encrypted less-than comparison with plaintext double. */
        virtual const Einteger operator<(double) const;
        /** @brief Encrypted less-than-or-equal comparison with plaintext
         * double. */
        virtual const Einteger operator<=(double) const;

        // Arithmetic operators
        using Einteger::operator+;
        using Einteger::operator+=;
        using Einteger::operator-;
        using Einteger::operator-=;
        using Einteger::operator*;
        using Einteger::operator*=;
        using Einteger::operator/;
        using Einteger::operator/=;

        /** @brief Encrypted addition (ciphertext-ciphertext). */
        virtual const Efixedpoint operator+(const Efixedpoint &) const;
        /** @brief Encrypted addition assignment (ciphertext-ciphertext). */
        virtual const Efixedpoint operator+=(const Efixedpoint &);
        /** @brief Encrypted subtraction (ciphertext-ciphertext). */
        virtual const Efixedpoint operator-(const Efixedpoint &) const;
        /** @brief Encrypted subtraction assignment (ciphertext-ciphertext). */
        virtual const Efixedpoint operator-=(const Efixedpoint &);
        /** @brief Encrypted multiplication (ciphertext-ciphertext). Resulting
         * frac_size is sum of inputs. */
        virtual const Efixedpoint operator*(const Efixedpoint &) const;
        /** @brief Encrypted multiplication assignment (ciphertext-ciphertext).
         */
        virtual const Efixedpoint operator*=(const Efixedpoint &);
        /** @brief Encrypted division (ciphertext-ciphertext). */
        virtual const Efixedpoint operator/(const Efixedpoint &) const;
        /** @brief Encrypted division assignment (ciphertext-ciphertext). */
        virtual const Efixedpoint operator/=(const Efixedpoint &);

        /** @brief Encrypted addition with plaintext double. */
        virtual const Efixedpoint operator+(double) const;
        /** @brief Encrypted addition assignment with plaintext double. */
        virtual const Efixedpoint operator+=(double);
        /** @brief Encrypted subtraction with plaintext double. */
        virtual const Efixedpoint operator-(double) const;
        /** @brief Encrypted subtraction assignment with plaintext double. */
        virtual const Efixedpoint operator-=(double);
        /** @brief Encrypted multiplication with plaintext double. */
        virtual const Efixedpoint operator*(double) const;
        /** @brief Encrypted multiplication assignment with plaintext double. */
        virtual const Efixedpoint operator*=(double);
        /** @brief Encrypted division with plaintext double. */
        virtual const Efixedpoint operator/(double) const;
        /** @brief Encrypted division assignment with plaintext double. */
        virtual const Efixedpoint operator/=(double);

        /** @brief Encrypted unary negation. */
        const Efixedpoint operator-() const;

        // Increment & Decrement operators
        /** @brief Pre-increment. */
        const Efixedpoint operator++();
        /** @brief Post-increment. */
        const Efixedpoint operator++(int);
        /** @brief Pre-decrement. */
        const Efixedpoint operator--();
        /** @brief Post-decrement. */
        const Efixedpoint operator--(int);

        // Shift operators
        /** @brief Bitwise left shift. */
        const Efixedpoint operator<<(int) const;
        /** @brief Bitwise left shift assignment. */
        const Efixedpoint operator<<=(int);
        /** @brief Bitwise right shift. */
        const Efixedpoint operator>>(int) const;
        /** @brief Bitwise right shift assignment. */
        const Efixedpoint operator>>=(int);

        // Assignment operators
        /** @brief Assignment from another Efixedpoint. */
        Efixedpoint &operator=(const Efixedpoint &);
        /** @brief Assignment from a plaintext double (encrypts the value). */
        Efixedpoint &operator=(double);

        // Type conversion
        using Einteger::operator bool;
        using Einteger::operator int8_t;
        using Einteger::operator uint8_t;
        using Einteger::operator int16_t;
        using Einteger::operator uint16_t;
        using Einteger::operator int32_t;
        using Einteger::operator uint32_t;
        using Einteger::operator int64_t;
        using Einteger::operator uint64_t;
        using Einteger::operator double;
        /** @brief Explicit conversion to a decrypted double. */
        virtual explicit operator double() const;
        /** @brief Converts fixed-point to integer by truncating the fractional
         * part. */
        Einteger toInteger() const;

        // Friend functions
        /**
         * @brief Decrypts and outputs the fixed-point value to a stream.
         * @param out The output stream.
         * @param obj The Efixedpoint object to decrypt and print.
         * @return A reference to the output stream.
         */
        friend ostream &operator<<(ostream &out, const Efixedpoint &obj);
        /**
         * @brief Plaintext-ciphertext equality comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if
         * equal).
         */
        friend const Einteger operator==(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext inequality comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if
         * not equal).
         */
        friend const Einteger operator!=(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext greater-than comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if a
         * > b).
         */
        friend const Einteger operator>(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext greater-than-or-equal comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if a
         * >= b).
         */
        friend const Einteger operator>=(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext less-than comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if a
         * < b).
         */
        friend const Einteger operator<(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext less-than-or-equal comparison.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return An Einteger representing the encrypted boolean result (1 if a
         * <= b).
         */
        friend const Einteger operator<=(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext addition.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return A new Efixedpoint representing the encrypted sum (a + b).
         */
        friend const Efixedpoint operator+(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext subtraction.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return A new Efixedpoint representing the encrypted difference (a -
         * b).
         */
        friend const Efixedpoint operator-(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext multiplication.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value.
         * @return A new Efixedpoint representing the encrypted product (a * b).
         */
        friend const Efixedpoint operator*(double a, const Efixedpoint &b);
        /**
         * @brief Plaintext-ciphertext division.
         * @param a The plaintext double value.
         * @param b The encrypted fixed-point value (divisor).
         * @return A new Efixedpoint representing the encrypted quotient (a /
         * b).
         */
        friend const Efixedpoint operator/(double a, const Efixedpoint &b);
    };
    ostream &operator<<(ostream &out, const Efixedpoint &obj);
    const Einteger operator==(double a, const Efixedpoint &b);
    const Einteger operator!=(double a, const Efixedpoint &b);
    const Einteger operator>(double a, const Efixedpoint &b);
    const Einteger operator>=(double a, const Efixedpoint &b);
    const Einteger operator<(double a, const Efixedpoint &b);
    const Einteger operator<=(double a, const Efixedpoint &b);
    const Efixedpoint operator+(double a, const Efixedpoint &b);
    const Efixedpoint operator-(double a, const Efixedpoint &b);
    const Efixedpoint operator*(double a, const Efixedpoint &b);
    const Efixedpoint operator/(double a, const Efixedpoint &b);

    template <size_t TOTAL_BITS, size_t FRAC_BITS, bool SIGNED>
    /**
     * @class EFix
     * @brief Template class for fixed-precision encrypted real numbers.
     *
     * Provides a convenient way to define types like EFix<32, 16, true> for
     * 32-bit fixed-point numbers with 16 bits of fractional precision.
     */
    class EFix : public Efixedpoint {
      public:
        /**
         * @brief Constructs an EFix from a double.
         * @param d Initial value (defaults to 0.0).
         * Encrypts and scales 'd' according to template parameters.
         */
        EFix(double d = 0) : Efixedpoint(d, TOTAL_BITS, FRAC_BITS, SIGNED) {}
        EFix(const Efixedpoint &other)
            : Efixedpoint(promote(other, TOTAL_BITS, FRAC_BITS), FRAC_BITS,
                          SIGNED) {}
    };
} // namespace computefhe