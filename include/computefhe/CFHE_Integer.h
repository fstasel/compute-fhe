#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <iostream>
using namespace std;

namespace computefhe {
    template <class T, bool isSigned>
    class CFHE_Integer {
        protected:
            FixedPoint data;
            size_t size;
            bool is_signed;

        public:
            CFHE_Integer();
            CFHE_Integer(T d);
            ~CFHE_Integer();
            static void Init(CryptoContextParam = CCPARAM_STD128_3, ArithmeticsEngineType = AE_OPTIMIZED);
            virtual CFHE_Integer<bool, false> operator==(const CFHE_Integer &);
            virtual CFHE_Integer<bool, false> operator!=(const CFHE_Integer &);
            virtual CFHE_Integer<bool, false> operator>(const CFHE_Integer &);
            virtual CFHE_Integer<bool, false> operator>=(const CFHE_Integer &);
            virtual CFHE_Integer<bool, false> operator<(const CFHE_Integer &);
            virtual CFHE_Integer<bool, false> operator<=(const CFHE_Integer &);
            virtual CFHE_Integer operator+(const CFHE_Integer &);
            virtual CFHE_Integer operator+(uint);
            virtual CFHE_Integer operator-(const CFHE_Integer &);
            virtual CFHE_Integer operator-(uint);
            virtual CFHE_Integer operator*(const CFHE_Integer &);
            virtual CFHE_Integer operator*(uint);
            virtual CFHE_Integer& operator=(uint n);
            virtual CFHE_Integer& operator=(FixedPoint n);
            virtual CFHE_Integer operator-();
            virtual operator uint() const;
            
            template<class U, bool S>
            friend ostream& operator<<(ostream &out, const CFHE_Integer<U, S>& obj);
    };
    
    template <class U, bool S>
    ostream& operator<<(ostream &out, const CFHE_Integer<U, S>& obj);

    using Ebool = CFHE_Integer<bool, false>;
    using Eint8 = CFHE_Integer<int8_t, true>;
    using Euint8 = CFHE_Integer<uint8_t, false>;
    using Eint16 = CFHE_Integer<int16_t, true>;
    using Euint16 = CFHE_Integer<uint16_t, false>;
    using Eint32 = CFHE_Integer<int32_t, true>;
    using Euint32 = CFHE_Integer<uint32_t, false>;
    using Eint64 = CFHE_Integer<int64_t, true>;
    using Euint64 = CFHE_Integer<uint64_t, false>;
}
