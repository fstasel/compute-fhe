#include <computefhe/CFHE_Integer.h>
#define SIZEOF(T) ((std::is_same_v<T, bool>) ? 1 : (sizeof(T) * 8))
using namespace computefhe;

static ComputeFHE *cfhe_base = nullptr;

void computefhe::Init(CryptoContextParam cc_param,
                      ArithmeticsEngineType ae_type) {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = new ComputeFHE(cc_param, ae_type);
}

template <class T, bool isSigned>
void computefhe::CFHE_Integer<T, isSigned>::fixSize(bool is_signed) {
    size_t s = SIZEOF(T);
    if (data.size() == s)
        return;
    if (data.size() > s) {
        data.resize(s);
        return;
    }
    LWECiphertext last = data.back();
    while (data.size() < s) {
        data.push_back(
            is_signed ? COPY_CT(last)
                      : cfhe_base->GetArithmeticsEngine()->GetConstantFalse());
    }
}

template <class T, bool isSigned> CFHE_Integer<T, isSigned>::CFHE_Integer() {
    if (cfhe_base == nullptr)
        Init();
    data = FixedPoint(SIZEOF(T));
    size = SIZEOF(T);
    is_signed = isSigned;
}

template <class T, bool isSigned> CFHE_Integer<T, isSigned>::CFHE_Integer(T d) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(d, SIZEOF(T));
    size = SIZEOF(T);
    is_signed = isSigned;
}

template <class T, bool isSigned>
computefhe::CFHE_Integer<T, isSigned>::CFHE_Integer(const FixedPoint &fp,
                                                    bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(fp.size());
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(fp[i]);
    }
    size = SIZEOF(T);
    this->is_signed = isSigned;
    fixSize(is_signed);
}

template <class T, bool isSigned>
computefhe::CFHE_Integer<T, isSigned>::CFHE_Integer(const CFHE_Integer &other) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(SIZEOF(T));
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(other.data[i]);
    }
    size = SIZEOF(T);
    is_signed = isSigned;
}

template <class T, bool isSigned> CFHE_Integer<T, isSigned>::~CFHE_Integer() {
    // empty
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator==(const CFHE_Integer &other) {
    return Ebool({cfhe_base->GetArithmeticsEngine()->CmpEq(data, other.data)},
                 false);
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator!=(const CFHE_Integer &other) {
    return Ebool(
        {cfhe_base->GetArithmeticsEngine()->CmpNotEq(data, other.data)}, false);
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator>(const CFHE_Integer &other) {
    if (isSigned) {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpGT(data, other.data)},
            false);
    } else {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpGT_U(data, other.data)},
            false);
    }
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator>=(const CFHE_Integer &other) {
    if (isSigned) {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpGTEq(data, other.data)},
            false);
    } else {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(data, other.data)},
            false);
    }
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator<(const CFHE_Integer &other) {
    if (isSigned) {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpLT(data, other.data)},
            false);
    } else {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpLT_U(data, other.data)},
            false);
    }
}

template <class T, bool isSigned>
Ebool CFHE_Integer<T, isSigned>::operator<=(const CFHE_Integer &other) {
    if (isSigned) {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpLTEq(data, other.data)},
            false);
    } else {
        return Ebool(
            {cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(data, other.data)},
            false);
    }
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator+(const CFHE_Integer &other) {
    return CFHE_Integer(
        cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data),
        isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator+(U other) {
    return *this + CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator+=(const CFHE_Integer &other) {
    data = cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data);
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator+=(U other) {
    return *this += CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator-(const CFHE_Integer &other) {
    return CFHE_Integer(
        cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data),
        isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-(U other) {
    return *this - CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator-=(const CFHE_Integer &other) {
    data = cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data);
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-=(U other) {
    return *this -= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator*(const CFHE_Integer &other) {
    return CFHE_Integer(
        cfhe_base->GetArithmeticsEngine()->Mul(data, other.data),
        isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator*(U other) {
    return *this * CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator*=(const CFHE_Integer &other) {
    data = cfhe_base->GetArithmeticsEngine()->Mul(data, other.data);
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator*=(U other) {
    return *this *= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator-() {
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->Neg(data), isSigned);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator&(const CFHE_Integer &other) {
    FixedPoint fp(SIZEOF(T));
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] = cfhe_base->GetBinFHEContext().EvalBinGate(
            lbcrypto::AND, data[i], other.data[i]);
    }
    return CFHE_Integer(fp, isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator&(U other) {
    return *this & CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator&=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetBinFHEContext().EvalBinGate(
            lbcrypto::AND, data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator&=(U other) {
    return *this &= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator|(const CFHE_Integer &other) {
    FixedPoint fp(SIZEOF(T));
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] = cfhe_base->GetBinFHEContext().EvalBinGate(lbcrypto::OR, data[i],
                                                          other.data[i]);
    }
    return CFHE_Integer(fp, isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator|(U other) {
    return *this | CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator|=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetBinFHEContext().EvalBinGate(
            lbcrypto::OR, data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator|=(U other) {
    return *this |= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator^(const CFHE_Integer &other) {
    FixedPoint fp(SIZEOF(T));
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] = cfhe_base->GetBinFHEContext().EvalBinGate(
            lbcrypto::XOR, data[i], other.data[i]);
    }
    return CFHE_Integer(fp, isSigned || other.is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator^(U other) {
    return *this ^ CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator^=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] = cfhe_base->GetBinFHEContext().EvalBinGate(
            lbcrypto::XOR, data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator^=(U other) {
    return *this ^= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned> CFHE_Integer<T, isSigned>::operator T() {
    return (T)cfhe_base->DecryptInt(data, size);
}

template <class T, bool isSigned>
template <class U, bool S>
CFHE_Integer<T, isSigned>::operator CFHE_Integer<U, S>() {
    return CFHE_Integer<U, S>(data, is_signed);
}

template <class U, bool S>
ostream &computefhe::operator<<(ostream &out, const CFHE_Integer<U, S> &obj) {
    out << (U)(cfhe_base->DecryptInt(obj.data, obj.size));
    return out;
}

// Define macros
#define CFHE_TYPES(X)                                                          \
    X(bool, false)                                                             \
    X(int8_t, true)                                                            \
    X(uint8_t, false)                                                          \
    X(int16_t, true)                                                           \
    X(uint16_t, false)                                                         \
    X(int32_t, true)                                                           \
    X(uint32_t, false)                                                         \
    X(int64_t, true)                                                           \
    X(uint64_t, false)

#define INSTANTIATE_CFHE_INTEGER(T, S)                                         \
    template class CFHE_Integer<T, S>;                                         \
    template std::ostream &computefhe::operator<< <T, S>(                      \
        std::ostream & out, const CFHE_Integer<T, S> &obj);

CFHE_TYPES(INSTANTIATE_CFHE_INTEGER)

#define INSTANTIATE_CAST(FROM_T, FROM_S)                                       \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<bool,         \
                                                                 false>();     \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<uint8_t,      \
                                                                 false>();     \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<uint16_t,     \
                                                                 false>();     \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<uint32_t,     \
                                                                 false>();     \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<uint64_t,     \
                                                                 false>();     \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<int8_t,       \
                                                                 true>();      \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<int16_t,      \
                                                                 true>();      \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<int32_t,      \
                                                                 true>();      \
    template CFHE_Integer<FROM_T, FROM_S>::operator CFHE_Integer<int64_t,      \
                                                                 true>();      \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator+=(int64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-=(int64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator-(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator*=(int64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator&=(int64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator|=(int64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(bool);                             \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(uint8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(uint16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(uint32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(uint64_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(int8_t);                           \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(int16_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(int32_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^(int64_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(bool);                            \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(uint8_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(uint16_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(uint32_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(uint64_t);                        \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(int8_t);                          \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(int16_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(int32_t);                         \
    template CFHE_Integer<FROM_T, FROM_S>                                      \
    CFHE_Integer<FROM_T, FROM_S>::operator^=(int64_t);

INSTANTIATE_CAST(bool, false)
INSTANTIATE_CAST(uint8_t, false)
INSTANTIATE_CAST(uint16_t, false)
INSTANTIATE_CAST(uint32_t, false)
INSTANTIATE_CAST(uint64_t, false)
INSTANTIATE_CAST(int8_t, true)
INSTANTIATE_CAST(int16_t, true)
INSTANTIATE_CAST(int32_t, true)
INSTANTIATE_CAST(int64_t, true)