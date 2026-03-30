#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <computefhe/ConditionManager.h>
#include <iostream>
using namespace std;

namespace computefhe {
    void Init(CryptoContextParam = CCPARAM_STD128_3,
              ArithmeticsEngineType = AE_OPTIMIZED);

    void Finalize();

    extern ComputeFHE *cfhe_base;

    class CFHE_Integer {
      protected:
        FixedPoint data;
        size_t size;
        bool sign;

        virtual void fixSize(bool is_signed);
        virtual int64_t sign_extend(uint64_t d, size_t n_digits);
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
        virtual CFHE_Integer operator==(const CFHE_Integer &);
        virtual CFHE_Integer operator!=(const CFHE_Integer &);
        virtual CFHE_Integer operator>(const CFHE_Integer &);
        virtual CFHE_Integer operator>=(const CFHE_Integer &);
        virtual CFHE_Integer operator<(const CFHE_Integer &);
        virtual CFHE_Integer operator<=(const CFHE_Integer &);
        virtual CFHE_Integer operator==(uint64_t);
        virtual CFHE_Integer operator!=(uint64_t);
        virtual CFHE_Integer operator>(uint64_t);
        virtual CFHE_Integer operator>=(uint64_t);
        virtual CFHE_Integer operator<(uint64_t);
        virtual CFHE_Integer operator<=(uint64_t);

        // Arithmetic operators
        virtual CFHE_Integer operator+(const CFHE_Integer &);
        virtual CFHE_Integer operator+=(const CFHE_Integer &);
        virtual CFHE_Integer operator-(const CFHE_Integer &);
        virtual CFHE_Integer operator-=(const CFHE_Integer &);
        virtual CFHE_Integer operator*(const CFHE_Integer &);
        virtual CFHE_Integer operator*=(const CFHE_Integer &);
        virtual CFHE_Integer operator+(uint64_t);
        virtual CFHE_Integer operator+=(uint64_t);
        virtual CFHE_Integer operator-(uint64_t);
        virtual CFHE_Integer operator-=(uint64_t);
        virtual CFHE_Integer operator*(uint64_t);
        virtual CFHE_Integer operator*=(uint64_t);
        virtual CFHE_Integer operator-();

        // Logic operators
        virtual CFHE_Integer operator&(const CFHE_Integer &);
        virtual CFHE_Integer operator&=(const CFHE_Integer &);
        virtual CFHE_Integer operator|(const CFHE_Integer &);
        virtual CFHE_Integer operator|=(const CFHE_Integer &);
        virtual CFHE_Integer operator^(const CFHE_Integer &);
        virtual CFHE_Integer operator^=(const CFHE_Integer &);
        virtual CFHE_Integer operator&(uint64_t);
        virtual CFHE_Integer operator&=(uint64_t);
        virtual CFHE_Integer operator|(uint64_t);
        virtual CFHE_Integer operator|=(uint64_t);
        virtual CFHE_Integer operator^(uint64_t);
        virtual CFHE_Integer operator^=(uint64_t);
        virtual CFHE_Integer operator!();
        virtual CFHE_Integer operator~();
        virtual CFHE_Integer operator&&(const CFHE_Integer &);
        virtual CFHE_Integer operator&&(uint64_t);
        virtual CFHE_Integer operator||(const CFHE_Integer &);
        virtual CFHE_Integer operator||(uint64_t);

        // Increment & Decrement operators
        virtual CFHE_Integer operator++();
        virtual CFHE_Integer operator++(int);
        virtual CFHE_Integer operator--();
        virtual CFHE_Integer operator--(int);

        // Shift operators
        virtual CFHE_Integer operator<<(int);
        virtual CFHE_Integer operator<<=(int);
        virtual CFHE_Integer operator>>(int);
        virtual CFHE_Integer operator>>=(int);

        // Assignment operators
        CFHE_Integer &operator=(const CFHE_Integer &);
        CFHE_Integer &operator=(uint64_t);

        // Type conversion
        virtual explicit operator bool();
        virtual explicit operator int8_t();
        virtual explicit operator uint8_t();
        virtual explicit operator int16_t();
        virtual explicit operator uint16_t();
        virtual explicit operator int32_t();
        virtual explicit operator uint32_t();
        virtual explicit operator int64_t();
        virtual explicit operator uint64_t();

        // Friend functions
        friend ostream &operator<<(ostream &out, const CFHE_Integer &obj);
    };

    ostream &operator<<(ostream &out, const CFHE_Integer &obj);
} // namespace computefhe
