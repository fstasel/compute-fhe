#include <computefhe/CFHE_Integer.h>
#include <computefhe/ConditionManager.h>

using namespace computefhe;

namespace computefhe {
    ComputeFHE *cfhe_base = nullptr;
}

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

void computefhe::CFHE_Integer::fixSize(bool is_signed) {
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

int64_t CFHE_Integer::sign_extend(uint64_t d, size_t n_digits) const {
    if (n_digits == 0 || n_digits >= 64)
        return (int64_t)d;
    uint64_t mask = 1ULL << (n_digits - 1);
    return (int64_t)((d ^ mask) - mask);
}

void CFHE_Integer::_sync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::register_variable((void *)this, &data);
    }
}

void CFHE_Integer::_desync_var() {
    if (ConditionManager::conditional_mode()) {
        ConditionManager::unregister_variable((void *)this);
    }
}

CFHE_Integer::CFHE_Integer(size_t n_digits, bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(0, n_digits);
    size = n_digits;
    sign = is_signed;
}

CFHE_Integer::CFHE_Integer(int64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt((uint64_t)d, n_digits);
    size = n_digits;
    sign = true;
}

CFHE_Integer::CFHE_Integer(uint64_t d, size_t n_digits) {
    if (cfhe_base == nullptr)
        Init();
    data = cfhe_base->GetConstantInt(d, n_digits);
    size = n_digits;
    sign = false;
}

CFHE_Integer::CFHE_Integer(const FixedPoint &fp, bool fp_sign, size_t n_digits,
                           bool is_signed) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(fp.size());
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(fp[i]);
    }
    size = n_digits;
    sign = is_signed;
    fixSize(fp_sign);
}

CFHE_Integer::CFHE_Integer(const CFHE_Integer &other) {
    if (cfhe_base == nullptr)
        Init();
    data.resize(other.size);
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(other.data[i]);
    }
    size = other.size;
    sign = other.sign;
}

CFHE_Integer::~CFHE_Integer() { _desync_var(); }

const FixedPoint &CFHE_Integer::getData() const { return data; }

size_t CFHE_Integer::getSize() const { return size; }

bool CFHE_Integer::isSigned() const { return sign; }

const CFHE_Integer CFHE_Integer::operator==(const CFHE_Integer &other) {
    if (size == other.size) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpEq(data, other.data)}, false,
            1UL, false);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    return CFHE_Integer(
        {cfhe_base->GetArithmeticsEngine()->CmpEq(data, t.data)}, false, 1UL,
        false);
}

const CFHE_Integer CFHE_Integer::operator!=(const CFHE_Integer &other) {
    if (size == other.size) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpNotEq(data, other.data)},
            false, 1UL, false);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    return CFHE_Integer(
        {cfhe_base->GetArithmeticsEngine()->CmpNotEq(data, t.data)}, false, 1UL,
        false);
}

const CFHE_Integer CFHE_Integer::operator>(const CFHE_Integer &other) {
    if (size == other.size) {
        if (sign) {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpGT(data, other.data)},
                false, 1UL, false);
        } else {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpGT_U(data, other.data)},
                false, 1UL, false);
        }
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    if (sign) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpGT(data, t.data)}, false,
            1UL, false);
    } else {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpGT_U(data, t.data)}, false,
            1UL, false);
    }
}

const CFHE_Integer CFHE_Integer::operator>=(const CFHE_Integer &other) {
    if (size == other.size) {
        if (sign) {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpGTEq(data, other.data)},
                false, 1UL, false);
        } else {
            return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(
                                    data, other.data)},
                                false, 1UL, false);
        }
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    if (sign) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpGTEq(data, t.data)}, false,
            1UL, false);
    } else {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(data, t.data)}, false,
            1UL, false);
    }
}

const CFHE_Integer CFHE_Integer::operator<(const CFHE_Integer &other) {
    if (size == other.size) {
        if (sign) {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpLT(data, other.data)},
                false, 1UL, false);
        } else {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpLT_U(data, other.data)},
                false, 1UL, false);
        }
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    if (sign) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpLT(data, t.data)}, false,
            1UL, false);
    } else {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpLT_U(data, t.data)}, false,
            1UL, false);
    }
}

const CFHE_Integer CFHE_Integer::operator<=(const CFHE_Integer &other) {
    if (size == other.size) {
        if (sign) {
            return CFHE_Integer(
                {cfhe_base->GetArithmeticsEngine()->CmpLTEq(data, other.data)},
                false, 1UL, false);
        } else {
            return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(
                                    data, other.data)},
                                false, 1UL, false);
        }
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    if (sign) {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpLTEq(data, t.data)}, false,
            1UL, false);
    } else {
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(data, t.data)}, false,
            1UL, false);
    }
}

const CFHE_Integer CFHE_Integer::operator==(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this == CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator!=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this != CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator>(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this > CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                size, sign);
}

const CFHE_Integer CFHE_Integer::operator>=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this >= CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator<(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this < CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                size, sign);
}

const CFHE_Integer CFHE_Integer::operator<=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext comparison
    return *this <= CFHE_Integer(cfhe_base->GetConstantInt(other, size), false,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator+(const CFHE_Integer &other) {
    if (size == other.size) {
        return CFHE_Integer(
            cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data), sign,
            size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->AddNC(data, t.data),
                        sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator+=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        data = cfhe_base->GetArithmeticsEngine()->AddNC(data, other.data);
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        data = cfhe_base->GetArithmeticsEngine()->AddNC(data, t.data);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator-(const CFHE_Integer &other) {
    if (size == other.size) {
        return CFHE_Integer(
            cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data), sign,
            size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->SubNC(data, t.data),
                        sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator-=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        data = cfhe_base->GetArithmeticsEngine()->SubNC(data, other.data);
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        data = cfhe_base->GetArithmeticsEngine()->SubNC(data, t.data);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator*(const CFHE_Integer &other) {
    if (size == other.size) {
        return CFHE_Integer(
            cfhe_base->GetArithmeticsEngine()->Mul(data, other.data), sign,
            size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->Mul(data, t.data),
                        sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator*=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        data = cfhe_base->GetArithmeticsEngine()->Mul(data, other.data);
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        data = cfhe_base->GetArithmeticsEngine()->Mul(data, t.data);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator+(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this + CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                size, sign);
}

const CFHE_Integer CFHE_Integer::operator+=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this += CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator-(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this - CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                size, sign);
}

const CFHE_Integer CFHE_Integer::operator-=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this -= CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator*(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this * CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                size, sign);
}

const CFHE_Integer CFHE_Integer::operator*=(uint64_t other) {
    // TODO: optimize this by using ciphertext-plaintext arithmetic
    return *this *= CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign,
                                 size, sign);
}

const CFHE_Integer CFHE_Integer::operator-() {
    return CFHE_Integer(cfhe_base->GetArithmeticsEngine()->Neg(data), sign,
                        size, sign);
}

const CFHE_Integer CFHE_Integer::operator&(const CFHE_Integer &other) {
    if (size == other.size) {
        FixedPoint fp(size);
        for (size_t i = 0; i < size; i++) {
            fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i],
                                                                other.data[i]);
        }
        return CFHE_Integer(fp, sign, size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], t.data[i]);
    }
    return CFHE_Integer(fp, sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator&=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        for (size_t i = 0; i < size; i++) {
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_AND(
                data[i], other.data[i]);
        }
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        for (size_t i = 0; i < size; i++) {
            data[i] =
                cfhe_base->GetArithmeticsEngine()->Gate_AND(data[i], t.data[i]);
        }
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator&(uint64_t other) {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = COPY_CT(data[i]);
        else
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator&=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (!bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator|(const CFHE_Integer &other) {
    if (size == other.size) {
        FixedPoint fp(size);
        for (size_t i = 0; i < size; i++) {
            fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i],
                                                               other.data[i]);
        }
        return CFHE_Integer(fp, sign, size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], t.data[i]);
    }
    return CFHE_Integer(fp, sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator|=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        for (size_t i = 0; i < size; i++) {
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i],
                                                                 other.data[i]);
        }
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        for (size_t i = 0; i < size; i++) {
            data[i] =
                cfhe_base->GetArithmeticsEngine()->Gate_OR(data[i], t.data[i]);
        }
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator|(uint64_t other) {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator|=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->GetConstantTrue();
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator^(const CFHE_Integer &other) {
    if (size == other.size) {
        FixedPoint fp(size);
        for (size_t i = 0; i < size; i++) {
            fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i],
                                                                other.data[i]);
        }
        return CFHE_Integer(fp, sign, size, sign);
    }
    CFHE_Integer t(other.data, other.sign, size, sign);
    FixedPoint fp(size);
    for (size_t i = 0; i < size; i++) {
        fp[i] = cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], t.data[i]);
    }
    return CFHE_Integer(fp, sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator^=(const CFHE_Integer &other) {
    _sync_var();
    if (size == other.size) {
        for (size_t i = 0; i < size; i++) {
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_XOR(
                data[i], other.data[i]);
        }
    } else {
        CFHE_Integer t(other.data, other.sign, size, sign);
        for (size_t i = 0; i < size; i++) {
            data[i] =
                cfhe_base->GetArithmeticsEngine()->Gate_XOR(data[i], t.data[i]);
        }
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator^(uint64_t other) {
    CFHE_Integer r(size, sign);
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            r.data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
        else
            r.data[i] = COPY_CT(data[i]);
    }
    return r;
}

const CFHE_Integer CFHE_Integer::operator^=(uint64_t other) {
    _sync_var();
    for (size_t i = 0; i < size; i++) {
        uint8_t bit = (other >> i) & 1;
        if (bit)
            data[i] = cfhe_base->GetArithmeticsEngine()->Gate_NOT(data[i]);
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator!() {
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_NOT(r)}, false,
                        1UL, false);
}

const CFHE_Integer CFHE_Integer::operator~() {
    return *this ^ 0xFFFFFFFFFFFFFFFFUL;
}

const CFHE_Integer CFHE_Integer::operator&&(const CFHE_Integer &other) {
    LWECiphertext r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_AND(r1, r2)},
                        false, 1UL, false);
}

const CFHE_Integer CFHE_Integer::operator&&(uint64_t other) {
    if (!other)
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->GetConstantFalse()}, false, 1UL,
            false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({r}, false, 1UL, false);
}

const CFHE_Integer CFHE_Integer::operator||(const CFHE_Integer &other) {
    LWECiphertext r1 = data[0];
    for (size_t i = 1; i < size; i++) {
        r1 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, data[i]);
    }
    LWECiphertext r2 = other.data[0];
    for (size_t i = 1; i < other.size; i++) {
        r2 = cfhe_base->GetArithmeticsEngine()->Gate_OR(r2, other.data[i]);
    }
    return CFHE_Integer({cfhe_base->GetArithmeticsEngine()->Gate_OR(r1, r2)},
                        false, 1UL, false);
}

const CFHE_Integer CFHE_Integer::operator||(uint64_t other) {
    if (other)
        return CFHE_Integer(
            {cfhe_base->GetArithmeticsEngine()->GetConstantTrue()}, false, 1UL,
            false);
    LWECiphertext r = data[0];
    for (size_t i = 1; i < size; i++) {
        r = cfhe_base->GetArithmeticsEngine()->Gate_OR(r, data[i]);
    }
    return CFHE_Integer({r}, false, 1UL, false);
}

const CFHE_Integer CFHE_Integer::operator++() {
    *this += 1;
    return *this;
}

const CFHE_Integer CFHE_Integer::operator++(int) {
    CFHE_Integer tmp = *this;
    *this += 1;
    return tmp;
}

const CFHE_Integer CFHE_Integer::operator--() {
    *this -= 1;
    return *this;
}

const CFHE_Integer CFHE_Integer::operator--(int) {
    CFHE_Integer tmp = *this;
    *this -= 1;
    return tmp;
}

const CFHE_Integer CFHE_Integer::operator<<(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        fp[i] = (i - s < 0)
                    ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                    : data[i - s];
    }
    return CFHE_Integer(fp, sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator<<=(int s) {
    _sync_var();
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = sz - 1; i >= 0; i--) {
        data[i] = (i - s < 0)
                      ? cfhe_base->GetArithmeticsEngine()->GetConstantFalse()
                      : data[i - s];
    }
    _sync_var();
    return *this;
}

const CFHE_Integer CFHE_Integer::operator>>(int s) {
    int sz = (int)size;
    FixedPoint fp(size);
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        fp[i] =
            (i + s >= sz)
                ? (sign ? data[fp.size() - 1]
                        : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    return CFHE_Integer(fp, sign, size, sign);
}

const CFHE_Integer CFHE_Integer::operator>>=(int s) {
    _sync_var();
    int sz = (int)size;
    s = clamp<int>(s, 0, size - 1);
    for (int i = 0; i < sz; i++) {
        data[i] =
            (i + s >= sz)
                ? (sign ? data[size - 1]
                        : cfhe_base->GetArithmeticsEngine()->GetConstantFalse())
                : data[i + s];
    }
    _sync_var();
    return *this;
}

CFHE_Integer &CFHE_Integer::operator=(const CFHE_Integer &other) {
    _sync_var();
    data.resize(other.data.size());
    for (size_t i = 0; i < data.size(); i++) {
        data[i] = COPY_CT(other.data[i]);
    }
    fixSize(other.sign);
    _sync_var();
    return *this;
}

CFHE_Integer &CFHE_Integer::operator=(uint64_t other) {
    _sync_var();
    *this =
        CFHE_Integer(cfhe_base->GetConstantInt(other, size), sign, size, sign);
    _sync_var();
    return *this;
}

CFHE_Integer::operator bool() const {
    // Client-mode only
    return (bool)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int8_t() const {
    // Client-mode only
    return (int8_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint8_t() const {
    // Client-mode only
    return (uint8_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int16_t() const {
    // Client-mode only
    return (int16_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint16_t() const {
    // Client-mode only
    return (uint16_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int32_t() const {
    // Client-mode only
    return (int32_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint32_t() const {
    // Client-mode only
    return (uint32_t)cfhe_base->DecryptInt(data, size);
}

CFHE_Integer::operator int64_t() const {
    // Client-mode only
    return (int64_t)sign_extend(cfhe_base->DecryptInt(data, size), size);
}

CFHE_Integer::operator uint64_t() const {
    // Client-mode only
    return (uint64_t)cfhe_base->DecryptInt(data, size);
}

ostream &computefhe::operator<<(ostream &out, const CFHE_Integer &obj) {
    // Client-mode only
    if (obj.sign) {
        out << const_cast<CFHE_Integer &>(obj).sign_extend(
            cfhe_base->DecryptInt(obj.data, obj.size), obj.size);
    } else
        out << (uint64_t)(cfhe_base->DecryptInt(obj.data, obj.size));
    return out;
}
