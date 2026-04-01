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

        virtual void fixSize(bool is_signed);
        virtual int64_t sign_extend(uint64_t d, size_t n_digits) const;
        void _sync_var();
        void _desync_var();

      public:
        CFHE_Integer(size_t n_digits, bool is_signed);
        CFHE_Integer(int64_t d, size_t n_digits);
        CFHE_Integer(uint64_t d, size_t n_digits);
        CFHE_Integer(const FixedPoint &fp, bool fp_sign, size_t n_digits,
                     bool is_signed);
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
        virtual const CFHE_Integer operator-() const;

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
        virtual const CFHE_Integer operator++();
        virtual const CFHE_Integer operator++(int);
        virtual const CFHE_Integer operator--();
        virtual const CFHE_Integer operator--(int);

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

        // Friend functions
        friend ostream &operator<<(ostream &out, const CFHE_Integer &obj);
    };

    ostream &operator<<(ostream &out, const CFHE_Integer &obj);
} // namespace computefhe
