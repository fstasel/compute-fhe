#include <cmath>
#include <computefhe/CFHE_Integer.h>
#include <computefhe/Evector.h>

using namespace computefhe;

Eitem::Eitem(Evector<CFHE_Integer> &vec, const CFHE_Integer &idx) : data(vec) {
    size_t n = vec.size();
    size_t bit_size =
        (n > 1) ? static_cast<size_t>(std::ceil(std::log2(n))) : 1;
    index = FixedPoint(bit_size);
    const FixedPoint &fp = idx.getData();
    for (size_t j = 0; j < bit_size; ++j) {
        if (j < fp.size())
            index[j] = fp[j];
        else
            index[j] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    p_index = 0;
    encrypted_index = true;
}

Eitem::Eitem(Evector<CFHE_Integer> &vec, const size_t idx)
    : data(vec), p_index(idx), encrypted_index(false) {
    // empty
}

Eitem::operator CFHE_Integer() const {
    if (encrypted_index) {
        // TODO: optimize this by using ciphertext-plaintext comparison
        LWECiphertext c = cfhe_base->GetArithmeticsEngine()->CmpEq(
            index, cfhe_base->GetConstantInt(0, index.size()));
        size_t n = data.at(0).getData().size();
        FixedPoint result(n);

        for (size_t d = 0; d < n; ++d) {
            result[d] = cfhe_base->GetArithmeticsEngine()->Gate_AND(
                c, data.at(0).getData()[d]);
        }
        for (size_t i = 1; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            c = cfhe_base->GetArithmeticsEngine()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            for (size_t d = 0; d < n; ++d) {
                result[d] = cfhe_base->GetArithmeticsEngine()->MulAdd(
                    c, data[i].getData()[d], result[d]);
            }
        }
        return CFHE_Integer(result, data.at(0).isSigned());
    }
    return data[p_index];
}

const CFHE_Integer &Eitem::operator=(const CFHE_Integer &value) {
    if (encrypted_index) {
        size_t n = data.at(0).getData().size();
        for (size_t i = 0; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            LWECiphertext c = cfhe_base->GetArithmeticsEngine()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            FixedPoint &target_fp = const_cast<FixedPoint &>(data[i].getData());
            for (size_t d = 0; d < n; ++d) {
                LWECiphertext v =
                    const_cast<CFHE_Integer &>(value).getData()[d];
                // TODO: try optimizing below logic
                target_fp[d] =
                    cfhe_base->GetArithmeticsEngine()->Mux(c, target_fp[d], v);
            }
        }
    } else {
        data[p_index] = value;
    }
    return value;
}

CFHE_Integer Eitem::operator+(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) + b;
}
CFHE_Integer Eitem::operator+(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) + b;
}
CFHE_Integer Eitem::operator-(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) - b;
}
CFHE_Integer Eitem::operator-(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) - b;
}
CFHE_Integer Eitem::operator*(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) * b;
}
CFHE_Integer Eitem::operator*(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) * b;
}
CFHE_Integer Eitem::operator&(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) & b;
}
CFHE_Integer Eitem::operator&(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) & b;
}
CFHE_Integer Eitem::operator|(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) | b;
}
CFHE_Integer Eitem::operator|(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) | b;
}
CFHE_Integer Eitem::operator^(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) ^ b;
}
CFHE_Integer Eitem::operator^(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) ^ b;
}

CFHE_Integer Eitem::operator==(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) == b;
}
CFHE_Integer Eitem::operator==(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) == b;
}
CFHE_Integer Eitem::operator!=(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) != b;
}
CFHE_Integer Eitem::operator!=(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) != b;
}
CFHE_Integer Eitem::operator>(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) > b;
}
CFHE_Integer Eitem::operator>(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) > b;
}
CFHE_Integer Eitem::operator>=(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) >= b;
}
CFHE_Integer Eitem::operator>=(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) >= b;
}
CFHE_Integer Eitem::operator<(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) < b;
}
CFHE_Integer Eitem::operator<(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) < b;
}
CFHE_Integer Eitem::operator<=(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) <= b;
}
CFHE_Integer Eitem::operator<=(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) <= b;
}

CFHE_Integer Eitem::operator&&(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) && b;
}
CFHE_Integer Eitem::operator&&(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) && b;
}
CFHE_Integer Eitem::operator||(const CFHE_Integer &b) const {
    return static_cast<CFHE_Integer>(*this) || b;
}
CFHE_Integer Eitem::operator||(uint64_t b) const {
    return static_cast<CFHE_Integer>(*this) || b;
}

CFHE_Integer Eitem::operator<<(int b) const {
    return static_cast<CFHE_Integer>(*this) << b;
}
CFHE_Integer Eitem::operator>>(int b) const {
    return static_cast<CFHE_Integer>(*this) >> b;
}

Eitem &Eitem::operator+=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) + b;
    return *this;
}
Eitem &Eitem::operator+=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) + b;
    return *this;
}
Eitem &Eitem::operator-=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) - b;
    return *this;
}
Eitem &Eitem::operator-=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) - b;
    return *this;
}
Eitem &Eitem::operator*=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) * b;
    return *this;
}
Eitem &Eitem::operator*=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) * b;
    return *this;
}
Eitem &Eitem::operator&=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) & b;
    return *this;
}
Eitem &Eitem::operator&=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) & b;
    return *this;
}
Eitem &Eitem::operator|=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) | b;
    return *this;
}
Eitem &Eitem::operator|=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) | b;
    return *this;
}
Eitem &Eitem::operator^=(const CFHE_Integer &b) {
    *this = static_cast<CFHE_Integer>(*this) ^ b;
    return *this;
}
Eitem &Eitem::operator^=(uint64_t b) {
    *this = static_cast<CFHE_Integer>(*this) ^ b;
    return *this;
}
Eitem &Eitem::operator<<=(int b) {
    *this = static_cast<CFHE_Integer>(*this) << b;
    return *this;
}
Eitem &Eitem::operator>>=(int b) {
    *this = static_cast<CFHE_Integer>(*this) >> b;
    return *this;
}

CFHE_Integer Eitem::operator!() const {
    return !static_cast<CFHE_Integer>(*this);
}
CFHE_Integer Eitem::operator~() const {
    return ~static_cast<CFHE_Integer>(*this);
}
CFHE_Integer Eitem::operator-() const {
    return -static_cast<CFHE_Integer>(*this);
}
CFHE_Integer Eitem::operator++() {
    CFHE_Integer val = static_cast<CFHE_Integer>(*this);
    ++val;
    *this = val;
    return val;
}
CFHE_Integer Eitem::operator++(int) {
    CFHE_Integer old = static_cast<CFHE_Integer>(*this);
    CFHE_Integer val = old;
    ++val;
    *this = val;
    return old;
}
CFHE_Integer Eitem::operator--() {
    CFHE_Integer val = static_cast<CFHE_Integer>(*this);
    --val;
    *this = val;
    return val;
}
CFHE_Integer Eitem::operator--(int) {
    CFHE_Integer old = static_cast<CFHE_Integer>(*this);
    CFHE_Integer val = old;
    --val;
    *this = val;
    return old;
}
