#pragma once

#include <computefhe/CFHETypes.h>
#include <computefhe/FixedPoint.h>
#include <iostream>
using namespace std;

namespace computefhe {
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
        static FixedPoint promote(const Einteger &a, size_t s);

      public:
        Einteger();
        Einteger(int64_t d);
        Einteger(size_t n_digits, bool is_signed);
        Einteger(int64_t d, size_t n_digits);
        Einteger(uint64_t d, size_t n_digits);
        Einteger(const FixedPoint &fp, bool is_signed);
        Einteger(const Einteger &other);
        virtual ~Einteger();

        const FixedPoint &getData() const;
        size_t getSize() const;
        bool isSigned() const;

        // Comparison operators
        virtual const Einteger operator==(const Einteger &) const;
        virtual const Einteger operator!=(const Einteger &) const;
        virtual const Einteger operator>(const Einteger &) const;
        virtual const Einteger operator>=(const Einteger &) const;
        virtual const Einteger operator<(const Einteger &) const;
        virtual const Einteger operator<=(const Einteger &) const;
        virtual const Einteger operator==(uint64_t) const;
        virtual const Einteger operator!=(uint64_t) const;
        virtual const Einteger operator>(uint64_t) const;
        virtual const Einteger operator>=(uint64_t) const;
        virtual const Einteger operator<(uint64_t) const;
        virtual const Einteger operator<=(uint64_t) const;

        // Arithmetic operators
        virtual const Einteger operator+(const Einteger &) const;
        virtual const Einteger operator+=(const Einteger &);
        virtual const Einteger operator-(const Einteger &) const;
        virtual const Einteger operator-=(const Einteger &);
        virtual const Einteger operator*(const Einteger &) const;
        virtual const Einteger operator*=(const Einteger &);
        virtual const Einteger operator/(const Einteger &) const;
        virtual const Einteger operator/=(const Einteger &);
        virtual const Einteger operator%(const Einteger &) const;
        virtual const Einteger operator%=(const Einteger &);
        virtual const Einteger operator+(uint64_t) const;
        virtual const Einteger operator+=(uint64_t);
        virtual const Einteger operator-(uint64_t) const;
        virtual const Einteger operator-=(uint64_t);
        virtual const Einteger operator*(uint64_t) const;
        virtual const Einteger operator*=(uint64_t);
        virtual const Einteger operator/(uint64_t) const;
        virtual const Einteger operator/=(uint64_t);
        virtual const Einteger operator%(uint64_t) const;
        virtual const Einteger operator%=(uint64_t);
        const Einteger operator-() const;

        // Logic operators
        virtual const Einteger operator&(const Einteger &) const;
        virtual const Einteger operator&=(const Einteger &);
        virtual const Einteger operator|(const Einteger &) const;
        virtual const Einteger operator|=(const Einteger &);
        virtual const Einteger operator^(const Einteger &) const;
        virtual const Einteger operator^=(const Einteger &);
        virtual const Einteger operator&(uint64_t) const;
        virtual const Einteger operator&=(uint64_t);
        virtual const Einteger operator|(uint64_t) const;
        virtual const Einteger operator|=(uint64_t);
        virtual const Einteger operator^(uint64_t) const;
        virtual const Einteger operator^=(uint64_t);
        virtual const Einteger operator!() const;
        virtual const Einteger operator~() const;
        virtual const Einteger operator&&(const Einteger &) const;
        virtual const Einteger operator&&(uint64_t) const;
        virtual const Einteger operator||(const Einteger &) const;
        virtual const Einteger operator||(uint64_t) const;

        // Increment & Decrement operators
        const Einteger operator++();
        const Einteger operator++(int);
        const Einteger operator--();
        const Einteger operator--(int);

        // Shift operators
        const Einteger operator<<(int) const;
        const Einteger operator<<=(int);
        const Einteger operator>>(int) const;
        const Einteger operator>>=(int);

        // Assignment operators
        Einteger &operator=(const Einteger &);
        Einteger &operator=(uint64_t);

        // Type conversion
        virtual explicit operator bool() const;
        virtual explicit operator int8_t() const;
        virtual explicit operator uint8_t() const;
        virtual explicit operator int16_t() const;
        virtual explicit operator uint16_t() const;
        virtual explicit operator int32_t() const;
        virtual explicit operator uint32_t() const;
        virtual explicit operator int64_t() const;
        virtual explicit operator uint64_t() const;
        virtual explicit operator double() const;

        // Friend functions
        friend ostream &operator<<(ostream &out, const Einteger &obj);
        friend const Einteger operator/(uint64_t a, const Einteger &b);
        friend const Einteger operator%(uint64_t a, const Einteger &b);
    };

    ostream &operator<<(ostream &out, const Einteger &obj);
    const Einteger operator/(uint64_t a, const Einteger &b);
    const Einteger operator%(uint64_t a, const Einteger &b);

    template <typename T, size_t BITS, bool SIGNED>
    class EInt : public Einteger {
      public:
        EInt(T d = 0) : Einteger((uint64_t)d, BITS) { this->sign = SIGNED; }
        EInt(const Einteger &other) : Einteger(promote(other, BITS), SIGNED) {}
    };

    using Ebool = EInt<bool, 1, false>;
    using Eint8 = EInt<int8_t, 8, true>;
    using Euint8 = EInt<uint8_t, 8, false>;
    using Eint16 = EInt<int16_t, 16, true>;
    using Euint16 = EInt<uint16_t, 16, false>;
    using Eint32 = EInt<int32_t, 32, true>;
    using Euint32 = EInt<uint32_t, 32, false>;
    using Eint64 = EInt<int64_t, 64, true>;
    using Euint64 = EInt<uint64_t, 64, false>;
} // namespace computefhe