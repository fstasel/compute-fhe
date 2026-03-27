#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <iostream>
using namespace std;

namespace computefhe {
    void Init(CryptoContextParam = CCPARAM_STD128_3,
              ArithmeticsEngineType = AE_OPTIMIZED);

    void Finalize();

    template <class T, bool isSigned> class CFHE_Integer {
      protected:
        FixedPoint data;
        size_t size;
        bool is_signed;

        virtual void fixSize(bool is_signed);

      public:
        template <class U, bool S> friend class CFHE_Integer;

        CFHE_Integer();
        CFHE_Integer(T d);
        CFHE_Integer(const FixedPoint &fp, bool is_signed);
        CFHE_Integer(const CFHE_Integer &other);
        virtual ~CFHE_Integer();

        // Comparison operators
        virtual CFHE_Integer<bool, false> operator==(const CFHE_Integer &);
        virtual CFHE_Integer<bool, false> operator!=(const CFHE_Integer &);
        virtual CFHE_Integer<bool, false> operator>(const CFHE_Integer &);
        virtual CFHE_Integer<bool, false> operator>=(const CFHE_Integer &);
        virtual CFHE_Integer<bool, false> operator<(const CFHE_Integer &);
        virtual CFHE_Integer<bool, false> operator<=(const CFHE_Integer &);
        template <class U> CFHE_Integer<bool, false> operator==(U);
        template <class U> CFHE_Integer<bool, false> operator!=(U);
        template <class U> CFHE_Integer<bool, false> operator>(U);
        template <class U> CFHE_Integer<bool, false> operator>=(U);
        template <class U> CFHE_Integer<bool, false> operator<(U);
        template <class U> CFHE_Integer<bool, false> operator<=(U);

        // Arithmetic operators
        virtual CFHE_Integer operator+(const CFHE_Integer &);
        template <class U> CFHE_Integer operator+(U);
        virtual CFHE_Integer operator+=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator+=(U);
        virtual CFHE_Integer operator-(const CFHE_Integer &);
        template <class U> CFHE_Integer operator-(U);
        virtual CFHE_Integer operator-=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator-=(U);
        virtual CFHE_Integer operator*(const CFHE_Integer &);
        template <class U> CFHE_Integer operator*(U);
        virtual CFHE_Integer operator*=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator*=(U);
        virtual CFHE_Integer operator-();

        // Logic operators
        virtual CFHE_Integer operator&(const CFHE_Integer &);
        template <class U> CFHE_Integer operator&(U);
        virtual CFHE_Integer operator&=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator&=(U);
        virtual CFHE_Integer operator|(const CFHE_Integer &);
        template <class U> CFHE_Integer operator|(U);
        virtual CFHE_Integer operator|=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator|=(U);
        virtual CFHE_Integer operator^(const CFHE_Integer &);
        template <class U> CFHE_Integer operator^(U);
        virtual CFHE_Integer operator^=(const CFHE_Integer &);
        template <class U> CFHE_Integer operator^=(U);
        template <class U, bool S>
        CFHE_Integer<bool, false> operator&&(const CFHE_Integer<U, S> &);
        template <class U> CFHE_Integer<bool, false> operator&&(U);
        template <class U, bool S>
        CFHE_Integer<bool, false> operator||(const CFHE_Integer<U, S> &);
        template <class U> CFHE_Integer<bool, false> operator||(U);
        virtual CFHE_Integer<bool, false> operator!();
        virtual CFHE_Integer operator~();

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

        // Type conversion
        virtual operator T();
        template <class U, bool S> operator CFHE_Integer<U, S>();

        // Friend functions
        template <class U, bool S>
        friend ostream &operator<<(ostream &out, const CFHE_Integer<U, S> &obj);
    };

    template <class U, bool S>
    ostream &operator<<(ostream &out, const CFHE_Integer<U, S> &obj);

    using Ebool = CFHE_Integer<bool, false>;
    using Eint8 = CFHE_Integer<int8_t, true>;
    using Euint8 = CFHE_Integer<uint8_t, false>;
    using Eint16 = CFHE_Integer<int16_t, true>;
    using Euint16 = CFHE_Integer<uint16_t, false>;
    using Eint32 = CFHE_Integer<int32_t, true>;
    using Euint32 = CFHE_Integer<uint32_t, false>;
    using Eint64 = CFHE_Integer<int64_t, true>;
    using Euint64 = CFHE_Integer<uint64_t, false>;
} // namespace computefhe
