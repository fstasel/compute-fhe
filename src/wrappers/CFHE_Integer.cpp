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

void computefhe::Finalize() {
    if (cfhe_base != nullptr)
        delete cfhe_base;
    cfhe_base = nullptr;
}

template <class T, bool isSigned>
void computefhe::CFHE_Integer<T, isSigned>::fixSize(bool is_signed) {
    size_t s = size;
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
    data = cfhe_base->GetConstantInt(0, SIZEOF(T));
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
computefhe::CFHE_Integer<T, isSigned>::CFHE_Integer(const CFHE_Integer &other)
    : CFHE_Integer(other.data, other.is_signed) {
    // empty
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
    if (is_signed) {
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
    if (is_signed) {
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
    if (is_signed) {
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
    if (is_signed) {
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
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator==(U other) {
    return *this == CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator!=(U other) {
    return *this != CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator>(U other) {
    return *this > CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator>=(U other) {
    return *this >= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator<(U other) {
    return *this < CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                std::is_signed_v<U>);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator<=(U other) {
    return *this <= CFHE_Integer(cfhe_base->GetConstantInt(other, size),
                                 std::is_signed_v<U>);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator+(const CFHE_Integer &other) {
    return CFHE_Integer(
        cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data), is_signed);
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
        cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data), is_signed);
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
        cfhe_base->GetArithmeticsEngine()->Mul(data, other.data), is_signed);
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
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->Neg(data),
                        is_signed);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator&(const CFHE_Integer &other) {
    FixedPoint fp(size);
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], other.data[i]);
    }
    return CFHE_Integer(fp, is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator&(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    CFHE_Integer<T, isSigned> r;
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (bit)
            r.data[i] = COPY_CT(data[i]);
        else
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return r;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator&=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator&=(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (!bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return *this;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator|(const CFHE_Integer &other) {
    FixedPoint fp(size);
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], other.data[i]);
    }
    return CFHE_Integer(fp, is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator|(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    CFHE_Integer<T, isSigned> r;
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator|=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator|=(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
    }
    return *this;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator^(const CFHE_Integer &other) {
    FixedPoint fp(size);
    for (size_t i = 0; i < fp.size(); i++) {
        fp[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], other.data[i]);
    }
    return CFHE_Integer(fp, is_signed);
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator^(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    CFHE_Integer<T, isSigned> r;
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned>
CFHE_Integer<T, isSigned>::operator^=(const CFHE_Integer &other) {
    for (size_t i = 0; i < size; i++) {
        data[i] =
            cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], other.data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator^=(U other) {
    uint64_t o = static_cast<uint64_t>(other);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (o >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
    }
    return *this;
}

template <class T, bool isSigned>
template <class U, bool S>
Ebool CFHE_Integer<T, isSigned>::operator&&(const CFHE_Integer<U, S> &other) {
    LWECiphertext r1 = data[0];
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return Ebool({cfhe_base->GetArithmeticsEngine()->Gate_AND(r1, r2)}, false);
}

template <class T, bool isSigned>
template <class U>
Ebool CFHE_Integer<T, isSigned>::operator&&(U other) {
    if (!other)
        return Ebool({cfhe_base->GetArithmeticsEngine()->GetConstantFalse()},
                     false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return Ebool({r}, false);
}

template <class T, bool isSigned>
template <class U, bool S>
Ebool CFHE_Integer<T, isSigned>::operator||(const CFHE_Integer<U, S> &other) {
    LWECiphertext r1 = data[0];
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return Ebool({cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, r2)}, false);
}

template <class T, bool isSigned>
template <class U>
Ebool CFHE_Integer<T, isSigned>::operator||(U other) {
    if (other)
        return Ebool({cfhe_base->GetArithmeticsEngine()->GetConstantTrue()},
                     false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return Ebool({r}, false);
}

template <class T, bool isSigned>
CFHE_Integer<bool, false> CFHE_Integer<T, isSigned>::operator!() {
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return Ebool({cfhe_base->GetArithmeticsEngine()->Gate_NOT(r)}, false);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator~() {
    return *this ^ 0xFFFFFFFFFFFFFFFFUL;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator++() {
    *this += 1;
    return *this;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator++(int) {
    CFHE_Integer tmp = *this;
    *this += 1;
    return tmp;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator--() {
    *this -= 1;
    return *this;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator--(int) {
    CFHE_Integer tmp = *this;
    *this -= 1;
    return tmp;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator<<(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0)
                    ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                    : data[i - s];
    }
    return CFHE_Integer<T, isSigned>(fp, isSigned);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator<<=(int s) {
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        data[i] = (i - s < 0)
                      ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                      : data[i - s];
    }
    return *this;
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator>>(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        fp[i] =
            (i + s >= sz)
                ? (is_signed
                       ? data[fp.size() - 1]
                       : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    return CFHE_Integer<T, isSigned>(fp, isSigned);
}

template <class T, bool isSigned>
CFHE_Integer<T, isSigned> CFHE_Integer<T, isSigned>::operator>>=(int s) {
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        data[i] =
            (i + s >= sz)
                ? (is_signed
                       ? data[size - 1]
                       : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    return *this;
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
        std::ostream & out, const CFHE_Integer<T, S> &obj);                    \
    template CFHE_Integer<T, S>::operator CFHE_Integer<bool, false>();         \
    template CFHE_Integer<T, S>::operator CFHE_Integer<uint8_t, false>();      \
    template CFHE_Integer<T, S>::operator CFHE_Integer<uint16_t, false>();     \
    template CFHE_Integer<T, S>::operator CFHE_Integer<uint32_t, false>();     \
    template CFHE_Integer<T, S>::operator CFHE_Integer<uint64_t, false>();     \
    template CFHE_Integer<T, S>::operator CFHE_Integer<int8_t, true>();        \
    template CFHE_Integer<T, S>::operator CFHE_Integer<int16_t, true>();       \
    template CFHE_Integer<T, S>::operator CFHE_Integer<int32_t, true>();       \
    template CFHE_Integer<T, S>::operator CFHE_Integer<int64_t, true>();       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator+=(int64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-=(int64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator-(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator*=(int64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator&=(int64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator|=(int64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(bool);           \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(uint8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(uint16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(uint32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(uint64_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(int8_t);         \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(int16_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(int32_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^(int64_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(bool);          \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(uint8_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(uint16_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(uint32_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(uint64_t);      \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(int8_t);        \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(int16_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(int32_t);       \
    template CFHE_Integer<T, S> CFHE_Integer<T, S>::operator^=(int64_t);       \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(bool);   \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(bool);   \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(bool);    \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(bool);   \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(bool);    \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(bool);   \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        uint8_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        uint8_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(uint8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        uint8_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(uint8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        uint8_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(          \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(          \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        uint16_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(          \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(          \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        uint32_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(          \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(          \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        uint64_t);                                                             \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(int8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(int8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(int8_t);  \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(int8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(int8_t);  \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(int8_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        int16_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        int16_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(int16_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        int16_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(int16_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        int16_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        int32_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        int32_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(int32_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        int32_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(int32_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        int32_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator==(         \
        int64_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator!=(         \
        int64_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>(int64_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator>=(         \
        int64_t);                                                              \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<(int64_t); \
    template CFHE_Integer<bool, false> CFHE_Integer<T, S>::operator<=(         \
        int64_t);                                                              \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<bool, false> &);                                    \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<uint8_t, false> &);                                 \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<uint16_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<uint32_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<uint64_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<int8_t, true> &);                                   \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<int16_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<int32_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator&&(                             \
        const CFHE_Integer<int64_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator&&(bool);                       \
    template Ebool CFHE_Integer<T, S>::operator&&(uint8_t);                    \
    template Ebool CFHE_Integer<T, S>::operator&&(uint16_t);                   \
    template Ebool CFHE_Integer<T, S>::operator&&(uint32_t);                   \
    template Ebool CFHE_Integer<T, S>::operator&&(uint64_t);                   \
    template Ebool CFHE_Integer<T, S>::operator&&(int8_t);                     \
    template Ebool CFHE_Integer<T, S>::operator&&(int16_t);                    \
    template Ebool CFHE_Integer<T, S>::operator&&(int32_t);                    \
    template Ebool CFHE_Integer<T, S>::operator&&(int64_t);                    \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<bool, false> &);                                    \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<uint8_t, false> &);                                 \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<uint16_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<uint32_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<uint64_t, false> &);                                \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<int8_t, true> &);                                   \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<int16_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<int32_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator||(                             \
        const CFHE_Integer<int64_t, true> &);                                  \
    template Ebool CFHE_Integer<T, S>::operator||(bool);                       \
    template Ebool CFHE_Integer<T, S>::operator||(uint8_t);                    \
    template Ebool CFHE_Integer<T, S>::operator||(uint16_t);                   \
    template Ebool CFHE_Integer<T, S>::operator||(uint32_t);                   \
    template Ebool CFHE_Integer<T, S>::operator||(uint64_t);                   \
    template Ebool CFHE_Integer<T, S>::operator||(int8_t);                     \
    template Ebool CFHE_Integer<T, S>::operator||(int16_t);                    \
    template Ebool CFHE_Integer<T, S>::operator||(int32_t);                    \
    template Ebool CFHE_Integer<T, S>::operator||(int64_t);

CFHE_TYPES(INSTANTIATE_CFHE_INTEGER)