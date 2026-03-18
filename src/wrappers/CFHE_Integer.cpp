#include <computefhe/CFHE_Integer.h>
#define SIZEOF(T) ((std::is_same_v<T, bool>) ? 1 : (sizeof(T) * 8))
using namespace computefhe;

static ComputeFHE* cfhe_base = nullptr;

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>::CFHE_Integer() {
    if (cfhe_base == nullptr)
        Init();
    data = FixedPoint(SIZEOF(T));
    size = SIZEOF(T);
    is_signed = isSigned;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned>::CFHE_Integer(T d) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(d, SIZEOF(T));
    size = SIZEOF(T);
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned>::~CFHE_Integer() {
    // empty
}

template<class T, bool isSigned>
void CFHE_Integer<T, isSigned>::Init(CryptoContextParam cc_param, ArithmeticsEngineType ae_type) {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = new ComputeFHE(cc_param, ae_type);
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator==(const CFHE_Integer& other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpEq(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator!=(const CFHE_Integer &other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpNotEq(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator>(const CFHE_Integer& other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpGT_U(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator>=(const CFHE_Integer& other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator<(const CFHE_Integer& other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpLT_U(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator<=(const CFHE_Integer& other) {
    auto res = cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(data, other.data);
    return cfhe_base->DecryptBool(res) ? true : false;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator+(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data);
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator+(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->AddNC(data,cfhe_base->GetConstantInt(other, size));
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data);
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->SubNC(data, cfhe_base->GetConstantInt(other, size));
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator*(const CFHE_Integer &other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->Mul(data, other.data);
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator*(uint other) {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->Mul(data, cfhe_base->GetConstantInt(other, size));
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned>& CFHE_Integer<T, isSigned>::operator=(uint n) {
    data = cfhe_base->GetConstantInt(n, size);
    return *this;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned>& CFHE_Integer<T, isSigned>::operator=(FixedPoint n) {
    this->data = n;
    return *this;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-() {
    CFHE_Integer tmp;
    tmp.size = size;
    tmp.data = cfhe_base->GetArithmeticsEngine()->Neg(data);
    return tmp;
}

template<class T, bool isSigned>
CFHE_Integer<T, isSigned>::operator uint() const {
    return cfhe_base->DecryptInt(data, size);
}

template<class U, bool S>
ostream& computefhe::operator<<(ostream &out, const CFHE_Integer<U, S>& obj) {
    out << cfhe_base->DecryptInt(obj.data, obj.size);
    return out;
}

template class CFHE_Integer<bool, false>;
template class CFHE_Integer<int8_t, true>;
template class CFHE_Integer<uint8_t, false>;
template class CFHE_Integer<int16_t, true>;
template class CFHE_Integer<uint16_t, false>;
template class CFHE_Integer<int32_t, true>;
template class CFHE_Integer<uint32_t, false>;
template class CFHE_Integer<int64_t, true>;
template class CFHE_Integer<uint64_t, false>;

template ostream& computefhe::operator<<<bool, false>(ostream &out, const CFHE_Integer<bool, false>& obj);
template ostream& computefhe::operator<<<int8_t, true>(ostream &out, const CFHE_Integer<int8_t, true>& obj);
template ostream& computefhe::operator<<<uint8_t, false>(ostream &out, const CFHE_Integer<uint8_t, false>& obj);
template ostream& computefhe::operator<<<int16_t, true>(ostream &out, const CFHE_Integer<int16_t, true>& obj);
template ostream& computefhe::operator<<<uint16_t, false>(ostream &out, const CFHE_Integer<uint16_t, false>& obj);
template ostream& computefhe::operator<<<int32_t, true>(ostream &out, const CFHE_Integer<int32_t, true>& obj);
template ostream& computefhe::operator<<<uint32_t, false>(ostream &out, const CFHE_Integer<uint32_t, false>& obj);
template ostream& computefhe::operator<<<int64_t, true>(ostream &out, const CFHE_Integer<int64_t, true>& obj);
template ostream& computefhe::operator<<<uint64_t, false>(ostream &out, const CFHE_Integer<uint64_t, false>& obj);
