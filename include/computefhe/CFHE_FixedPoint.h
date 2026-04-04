#pragma once

#include <computefhe/CFHE_Integer.h>

namespace computefhe {
    class CFHE_FixedPoint : public CFHE_Integer {
      protected:
        size_t frac_size;

        static FixedPoint double2fp(double d, size_t n_digits, size_t n_frac);
        static void promote(const CFHE_FixedPoint &a, const CFHE_FixedPoint &b,
                            FixedPoint &a_out, FixedPoint &b_out,
                            size_t &n_digits_out, size_t &n_frac_out,
                            bool &sign_out);
        static FixedPoint promote(const CFHE_FixedPoint &a, size_t n_digits,
                                  size_t n_frac);

      public:
        CFHE_FixedPoint(size_t n_digits, size_t n_frac, bool is_signed);
        CFHE_FixedPoint(double d, size_t n_digits, size_t n_frac,
                        bool is_signed);
        CFHE_FixedPoint(const FixedPoint &fp, size_t n_frac, bool is_signed);
        CFHE_FixedPoint(const CFHE_FixedPoint &other);
        CFHE_FixedPoint(const CFHE_Integer &other);

        size_t getFracSize() const;
        void setFracSize(size_t);

        // Comparison operators
        using CFHE_Integer::operator==;
        using CFHE_Integer::operator!=;
        using CFHE_Integer::operator>;
        using CFHE_Integer::operator>=;
        using CFHE_Integer::operator<;
        using CFHE_Integer::operator<=;
        virtual const CFHE_Integer operator==(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator!=(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator>(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator>=(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator<(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator<=(const CFHE_FixedPoint &) const;
        virtual const CFHE_Integer operator==(double) const;
        virtual const CFHE_Integer operator!=(double) const;
        virtual const CFHE_Integer operator>(double) const;
        virtual const CFHE_Integer operator>=(double) const;
        virtual const CFHE_Integer operator<(double) const;
        virtual const CFHE_Integer operator<=(double) const;

        // Arithmetic operators
        using CFHE_Integer::operator+;
        using CFHE_Integer::operator+=;
        using CFHE_Integer::operator-;
        using CFHE_Integer::operator-=;
        using CFHE_Integer::operator*;
        using CFHE_Integer::operator*=;
        virtual const CFHE_FixedPoint operator+(const CFHE_FixedPoint &) const;
        virtual const CFHE_FixedPoint operator+=(const CFHE_FixedPoint &);
        virtual const CFHE_FixedPoint operator-(const CFHE_FixedPoint &) const;
        virtual const CFHE_FixedPoint operator-=(const CFHE_FixedPoint &);
        virtual const CFHE_FixedPoint operator*(const CFHE_FixedPoint &) const;
        virtual const CFHE_FixedPoint operator*=(const CFHE_FixedPoint &);
        virtual const CFHE_FixedPoint operator+(double) const;
        virtual const CFHE_FixedPoint operator+=(double);
        virtual const CFHE_FixedPoint operator-(double) const;
        virtual const CFHE_FixedPoint operator-=(double);
        virtual const CFHE_FixedPoint operator*(double) const;
        virtual const CFHE_FixedPoint operator*=(double);
        const CFHE_FixedPoint operator-() const;

        // TODO:
        // Increment & Decrement operators
        // const CFHE_FixedPoint operator++();
        // const CFHE_FixedPoint operator++(int);
        // const CFHE_FixedPoint operator--();
        // const CFHE_FixedPoint operator--(int);

        // Assignment operators
        CFHE_FixedPoint &operator=(const CFHE_FixedPoint &);
        CFHE_FixedPoint &operator=(double);

        // Type conversion
        using CFHE_Integer::operator bool;
        using CFHE_Integer::operator int8_t;
        using CFHE_Integer::operator uint8_t;
        using CFHE_Integer::operator int16_t;
        using CFHE_Integer::operator uint16_t;
        using CFHE_Integer::operator int32_t;
        using CFHE_Integer::operator uint32_t;
        using CFHE_Integer::operator int64_t;
        using CFHE_Integer::operator uint64_t;
        using CFHE_Integer::operator double;
        virtual explicit operator double() const;
        CFHE_Integer toInteger() const;

        // Friend functions
        friend ostream &operator<<(ostream &out, const CFHE_FixedPoint &obj);
    };
    ostream &operator<<(ostream &out, const CFHE_FixedPoint &obj);

} // namespace computefhe