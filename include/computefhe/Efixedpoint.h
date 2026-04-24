#pragma once

#include <computefhe/Einteger.h>

namespace computefhe {
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
        Efixedpoint();
        Efixedpoint(size_t n_digits, size_t n_frac, bool is_signed);
        Efixedpoint(double d, size_t n_digits, size_t n_frac, bool is_signed);
        Efixedpoint(const FixedPoint &fp, size_t n_frac, bool is_signed);
        Efixedpoint(const Efixedpoint &other);
        Efixedpoint(const Einteger &other);

        size_t getFracSize() const;
        void setFracSize(size_t);

        // Comparison operators
        using Einteger::operator==;
        using Einteger::operator!=;
        using Einteger::operator>;
        using Einteger::operator>=;
        using Einteger::operator<;
        using Einteger::operator<=;
        virtual const Einteger operator==(const Efixedpoint &) const;
        virtual const Einteger operator!=(const Efixedpoint &) const;
        virtual const Einteger operator>(const Efixedpoint &) const;
        virtual const Einteger operator>=(const Efixedpoint &) const;
        virtual const Einteger operator<(const Efixedpoint &) const;
        virtual const Einteger operator<=(const Efixedpoint &) const;
        virtual const Einteger operator==(double) const;
        virtual const Einteger operator!=(double) const;
        virtual const Einteger operator>(double) const;
        virtual const Einteger operator>=(double) const;
        virtual const Einteger operator<(double) const;
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
        virtual const Efixedpoint operator+(const Efixedpoint &) const;
        virtual const Efixedpoint operator+=(const Efixedpoint &);
        virtual const Efixedpoint operator-(const Efixedpoint &) const;
        virtual const Efixedpoint operator-=(const Efixedpoint &);
        virtual const Efixedpoint operator*(const Efixedpoint &) const;
        virtual const Efixedpoint operator*=(const Efixedpoint &);
        virtual const Efixedpoint operator/(const Efixedpoint &) const;
        virtual const Efixedpoint operator/=(const Efixedpoint &);
        virtual const Efixedpoint operator+(double) const;
        virtual const Efixedpoint operator+=(double);
        virtual const Efixedpoint operator-(double) const;
        virtual const Efixedpoint operator-=(double);
        virtual const Efixedpoint operator*(double) const;
        virtual const Efixedpoint operator*=(double);
        virtual const Efixedpoint operator/(double) const;
        virtual const Efixedpoint operator/=(double);
        const Efixedpoint operator-() const;

        // Increment & Decrement operators
        const Efixedpoint operator++();
        const Efixedpoint operator++(int);
        const Efixedpoint operator--();
        const Efixedpoint operator--(int);

        // Shift operators
        const Efixedpoint operator<<(int) const;
        const Efixedpoint operator<<=(int);
        const Efixedpoint operator>>(int) const;
        const Efixedpoint operator>>=(int);

        // Assignment operators
        Efixedpoint &operator=(const Efixedpoint &);
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
        virtual explicit operator double() const;
        Einteger toInteger() const;

        // Friend functions
        friend ostream &operator<<(ostream &out, const Efixedpoint &obj);
        friend const Efixedpoint operator/(double a, const Efixedpoint &b);

        // TODO: Arithmetic friend operators for double type
        // TODO: Comparison friend operators for double type
    };
    ostream &operator<<(ostream &out, const Efixedpoint &obj);
    const Efixedpoint operator/(double a, const Efixedpoint &b);

    template <size_t TOTAL_BITS, size_t FRAC_BITS, bool SIGNED>
    class EFix : public Efixedpoint {
      public:
        EFix(double d = 0) : Efixedpoint(d, TOTAL_BITS, FRAC_BITS, SIGNED) {}
        EFix(const Efixedpoint &other)
            : Efixedpoint(promote(other, TOTAL_BITS, FRAC_BITS), FRAC_BITS,
                          SIGNED) {}
    };
} // namespace computefhe