#pragma once

#include <computefhe/BaseALU.h>
#include <computefhe/ComputeFHE.h>
#include <computefhe/ConditionManager.h>
#include <iostream>
using namespace std;

namespace computefhe {
    void Init(CryptoContextParam = CCPARAM_STD128_3, ALUType = ALU_OPTIMIZED,
              bool = false, bool = false);
    void Finalize();

    extern ComputeFHE *cfhe_base;
    extern bool CLIENT_MODE;

    class CFHE_Integer {
      protected:
        FixedPoint data;
        size_t size;
        bool sign;

        static int64_t sign_extend(uint64_t d, size_t n_digits);
        void _sync_var();
        void _desync_var();
        static bool promote(const CFHE_Integer &a, const CFHE_Integer &b,
                            FixedPoint &a_out, FixedPoint &b_out);
        static FixedPoint promote(const CFHE_Integer &a, size_t s);

      public:
        CFHE_Integer();
        CFHE_Integer(int64_t d);
        CFHE_Integer(size_t n_digits, bool is_signed);
        CFHE_Integer(int64_t d, size_t n_digits);
        CFHE_Integer(uint64_t d, size_t n_digits);
        CFHE_Integer(const FixedPoint &fp, bool is_signed);
        CFHE_Integer(const CFHE_Integer &other);
        virtual ~CFHE_Integer();

        const FixedPoint &getData() const;
        size_t getSize() const;
        bool isSigned() const;

        // Comparison operators
        virtual const CFHE_Integer operator==(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator!=(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator>(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator>=(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator<(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator<=(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator==(uint64_t) const;
        virtual const CFHE_Integer operator!=(uint64_t) const;
        virtual const CFHE_Integer operator>(uint64_t) const;
        virtual const CFHE_Integer operator>=(uint64_t) const;
        virtual const CFHE_Integer operator<(uint64_t) const;
        virtual const CFHE_Integer operator<=(uint64_t) const;

        // Arithmetic operators
        virtual const CFHE_Integer operator+(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator+=(const CFHE_Integer &);
        virtual const CFHE_Integer operator-(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator-=(const CFHE_Integer &);
        virtual const CFHE_Integer operator*(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator*=(const CFHE_Integer &);
        virtual const CFHE_Integer operator+(uint64_t) const;
        virtual const CFHE_Integer operator+=(uint64_t);
        virtual const CFHE_Integer operator-(uint64_t) const;
        virtual const CFHE_Integer operator-=(uint64_t);
        virtual const CFHE_Integer operator*(uint64_t) const;
        virtual const CFHE_Integer operator*=(uint64_t);
        const CFHE_Integer operator-() const;

        // Logic operators
        virtual const CFHE_Integer operator&(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator&=(const CFHE_Integer &);
        virtual const CFHE_Integer operator|(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator|=(const CFHE_Integer &);
        virtual const CFHE_Integer operator^(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator^=(const CFHE_Integer &);
        virtual const CFHE_Integer operator&(uint64_t) const;
        virtual const CFHE_Integer operator&=(uint64_t);
        virtual const CFHE_Integer operator|(uint64_t) const;
        virtual const CFHE_Integer operator|=(uint64_t);
        virtual const CFHE_Integer operator^(uint64_t) const;
        virtual const CFHE_Integer operator^=(uint64_t);
        virtual const CFHE_Integer operator!() const;
        virtual const CFHE_Integer operator~() const;
        virtual const CFHE_Integer operator&&(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator&&(uint64_t) const;
        virtual const CFHE_Integer operator||(const CFHE_Integer &) const;
        virtual const CFHE_Integer operator||(uint64_t) const;

        // Increment & Decrement operators
        const CFHE_Integer operator++();
        const CFHE_Integer operator++(int);
        const CFHE_Integer operator--();
        const CFHE_Integer operator--(int);

        // Shift operators
        const CFHE_Integer operator<<(int);
        const CFHE_Integer operator<<=(int);
        const CFHE_Integer operator>>(int);
        const CFHE_Integer operator>>=(int);

        // Assignment operators
        CFHE_Integer &operator=(const CFHE_Integer &);
        CFHE_Integer &operator=(uint64_t);

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
        friend ostream &operator<<(ostream &out, const CFHE_Integer &obj);
    };

    ostream &operator<<(ostream &out, const CFHE_Integer &obj);

    template <typename T, size_t BITS, bool SIGNED>
    class EInt : public CFHE_Integer {
      public:
        EInt(T d = 0) : CFHE_Integer((uint64_t)d, BITS) { this->sign = SIGNED; }
        EInt(const CFHE_Integer &other)
            : CFHE_Integer(promote(other, BITS), SIGNED) {}
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