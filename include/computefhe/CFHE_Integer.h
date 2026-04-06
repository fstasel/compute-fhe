#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <computefhe/ConditionManager.h>
#include <iostream>
using namespace std;

namespace computefhe {
    void Init(CryptoContextParam = CCPARAM_STD128_3,
              ArithmeticsEngineType = AE_OPTIMIZED, bool = false);
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
        virtual const CFHE_Integer operator<<(int);
        virtual const CFHE_Integer operator<<=(int);
        virtual const CFHE_Integer operator>>(int);
        virtual const CFHE_Integer operator>>=(int);

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
    class EType : public CFHE_Integer {
      public:
        EType(T d = 0) : CFHE_Integer((uint64_t)d, BITS) {
            this->sign = SIGNED;
        }
        EType(const CFHE_Integer &other)
            : CFHE_Integer(promote(other, BITS), SIGNED) {}
    };

    using Ebool = EType<bool, 1, false>;
    using Eint8 = EType<int8_t, 8, true>;
    using Euint8 = EType<uint8_t, 8, false>;
    using Eint16 = EType<int16_t, 16, true>;
    using Euint16 = EType<uint16_t, 16, false>;
    using Eint32 = EType<int32_t, 32, true>;
    using Euint32 = EType<uint32_t, 32, false>;
    using Eint64 = EType<int64_t, 64, true>;
    using Euint64 = EType<uint64_t, 64, false>;
} // namespace computefhe