#include <cmath>
#include <computefhe/Evector.h>

using namespace computefhe;

template <typename T, typename U>
Eitem<T, U>::Eitem(Evector<T> &vec, const CFHE_Integer &idx) : data(vec) {
    size_t n = vec.size();
    size_t bit_size =
        (n > 1) ? static_cast<size_t>(std::ceil(std::log2(n))) : 1;
    index = FixedPoint(bit_size);
    const FixedPoint &fp = idx.getData();
    for (size_t j = 0; j < bit_size; ++j) {
        if (j < fp.size())
            index[j] = fp[j];
        else
            index[j] = cfhe_base->GetALU()->GetConstantFalse();
    }
    p_index = 0;
    encrypted_index = true;
}

template <typename T, typename U>
Eitem<T, U>::Eitem(Evector<T> &vec, const size_t idx)
    : data(vec), p_index(idx), encrypted_index(false) {
    // empty
}

template <typename T, typename U> Eitem<T, U>::operator T() const {
    if (encrypted_index) {
        // TODO: optimize this by using ciphertext-plaintext comparison
        BinaryDigit c = cfhe_base->GetALU()->CmpEq(
            index, cfhe_base->GetConstantInt(0, index.size()));
        size_t n = data.at(0).getData().size();
        FixedPoint result(n);

        for (size_t d = 0; d < n; ++d) {
            result[d] =
                cfhe_base->GetALU()->Gate_AND(c, data.at(0).getData()[d]);
        }
        for (size_t i = 1; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            c = cfhe_base->GetALU()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            for (size_t d = 0; d < n; ++d) {
                result[d] = cfhe_base->GetALU()->MulAdd(c, data[i].getData()[d],
                                                        result[d]);
            }
        }
        return CFHE_Integer(result, data.at(0).isSigned());
    }
    return data[p_index];
}

template <> Eitem<CFHE_FixedPoint, double>::operator CFHE_FixedPoint() const {
    if (encrypted_index) {
        // TODO: optimize this by using ciphertext-plaintext comparison
        BinaryDigit c = cfhe_base->GetALU()->CmpEq(
            index, cfhe_base->GetConstantInt(0, index.size()));
        size_t n = data.at(0).getData().size();
        FixedPoint result(n);

        for (size_t d = 0; d < n; ++d) {
            result[d] =
                cfhe_base->GetALU()->Gate_AND(c, data.at(0).getData()[d]);
        }
        for (size_t i = 1; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            c = cfhe_base->GetALU()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            for (size_t d = 0; d < n; ++d) {
                result[d] = cfhe_base->GetALU()->MulAdd(c, data[i].getData()[d],
                                                        result[d]);
            }
        }
        return CFHE_FixedPoint(result, data.at(0).getFracSize(),
                               data.at(0).isSigned());
    }
    return data[p_index];
}

template <typename T, typename U>
const T &Eitem<T, U>::operator=(const T &value) {
    if (encrypted_index) {
        size_t n = data.at(0).getData().size();
        for (size_t i = 0; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            BinaryDigit c = cfhe_base->GetALU()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            FixedPoint &target_fp = const_cast<FixedPoint &>(data[i].getData());
            for (size_t d = 0; d < n; ++d) {
                BinaryDigit v = const_cast<T &>(value).getData()[d];
                // TODO: try optimizing below logic
                target_fp[d] = cfhe_base->GetALU()->Mux(c, target_fp[d], v);
            }
        }
    } else {
        data[p_index] = value;
    }
    return value;
}

template <typename T, typename U> T Eitem<T, U>::operator+(const T &b) const {
    return static_cast<T>(*this) + b;
}

template <typename T, typename U> T Eitem<T, U>::operator+(U b) const {
    return static_cast<T>(*this) + b;
}

template <typename T, typename U> T Eitem<T, U>::operator-(const T &b) const {
    return static_cast<T>(*this) - b;
}

template <typename T, typename U> T Eitem<T, U>::operator-(U b) const {
    return static_cast<T>(*this) - b;
}

template <typename T, typename U> T Eitem<T, U>::operator*(const T &b) const {
    return static_cast<T>(*this) * b;
}

template <typename T, typename U> T Eitem<T, U>::operator*(U b) const {
    return static_cast<T>(*this) * b;
}

template <typename T, typename U> T Eitem<T, U>::operator&(const T &b) const {
    return static_cast<T>(*this) & b;
}

template <typename T, typename U> T Eitem<T, U>::operator&(U b) const {
    return static_cast<T>(*this) & b;
}

template <typename T, typename U> T Eitem<T, U>::operator|(const T &b) const {
    return static_cast<T>(*this) | b;
}

template <typename T, typename U> T Eitem<T, U>::operator|(U b) const {
    return static_cast<T>(*this) | b;
}

template <typename T, typename U> T Eitem<T, U>::operator^(const T &b) const {
    return static_cast<T>(*this) ^ b;
}

template <typename T, typename U> T Eitem<T, U>::operator^(U b) const {
    return static_cast<T>(*this) ^ b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator==(const T &b) const {
    return static_cast<T>(*this) == b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator==(U b) const {
    return static_cast<T>(*this) == b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator!=(const T &b) const {
    return static_cast<T>(*this) != b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator!=(U b) const {
    return static_cast<T>(*this) != b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator>(const T &b) const {
    return static_cast<T>(*this) > b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator>(U b) const {
    return static_cast<T>(*this) > b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator>=(const T &b) const {
    return static_cast<T>(*this) >= b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator>=(U b) const {
    return static_cast<T>(*this) >= b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator<(const T &b) const {
    return static_cast<T>(*this) < b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator<(U b) const {
    return static_cast<T>(*this) < b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator<=(const T &b) const {
    return static_cast<T>(*this) <= b;
}

template <typename T, typename U>
CFHE_Integer Eitem<T, U>::operator<=(U b) const {
    return static_cast<T>(*this) <= b;
}

template <typename T, typename U> T Eitem<T, U>::operator&&(const T &b) const {
    return static_cast<T>(*this) && b;
}

template <typename T, typename U> T Eitem<T, U>::operator&&(U b) const {
    return static_cast<T>(*this) && b;
}

template <typename T, typename U> T Eitem<T, U>::operator||(const T &b) const {
    return static_cast<T>(*this) || b;
}

template <typename T, typename U> T Eitem<T, U>::operator||(U b) const {
    return static_cast<T>(*this) || b;
}

template <typename T, typename U> T Eitem<T, U>::operator<<(int b) const {
    return static_cast<T>(*this) << b;
}

template <typename T, typename U> T Eitem<T, U>::operator>>(int b) const {
    return static_cast<T>(*this) >> b;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator+=(const T &b) {
    *this = static_cast<T>(*this) + b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator+=(U b) {
    *this = static_cast<T>(*this) + b;
    return *this;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator-=(const T &b) {
    *this = static_cast<T>(*this) - b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator-=(U b) {
    *this = static_cast<T>(*this) - b;
    return *this;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator*=(const T &b) {
    *this = static_cast<T>(*this) * b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator*=(U b) {
    *this = static_cast<T>(*this) * b;
    return *this;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator&=(const T &b) {
    *this = static_cast<T>(*this) & b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator&=(U b) {
    *this = static_cast<T>(*this) & b;
    return *this;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator|=(const T &b) {
    *this = static_cast<T>(*this) | b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator|=(U b) {
    *this = static_cast<T>(*this) | b;
    return *this;
}

template <typename T, typename U>
Eitem<T, U> &Eitem<T, U>::operator^=(const T &b) {
    *this = static_cast<T>(*this) ^ b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator^=(U b) {
    *this = static_cast<T>(*this) ^ b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator<<=(int b) {
    *this = static_cast<T>(*this) << b;
    return *this;
}

template <typename T, typename U> Eitem<T, U> &Eitem<T, U>::operator>>=(int b) {
    *this = static_cast<T>(*this) >> b;
    return *this;
}

template <typename T, typename U> T Eitem<T, U>::operator!() const {
    return !static_cast<T>(*this);
}

template <typename T, typename U> T Eitem<T, U>::operator~() const {
    return ~static_cast<T>(*this);
}

template <typename T, typename U> T Eitem<T, U>::operator-() const {
    return -static_cast<T>(*this);
}

template <typename T, typename U> T Eitem<T, U>::operator++() {
    T val = static_cast<T>(*this);
    ++val;
    *this = val;
    return val;
}

template <typename T, typename U> T Eitem<T, U>::operator++(int) {
    T old = static_cast<T>(*this);
    T val = old;
    ++val;
    *this = val;
    return old;
}

template <typename T, typename U> T Eitem<T, U>::operator--() {
    T val = static_cast<T>(*this);
    --val;
    *this = val;
    return val;
}

template <typename T, typename U> T Eitem<T, U>::operator--(int) {
    T old = static_cast<T>(*this);
    T val = old;
    --val;
    *this = val;
    return old;
}

template class Evector<CFHE_Integer>;
template class Eitem<CFHE_Integer, uint64_t>;
template class Evector<CFHE_FixedPoint>;
template class Eitem<CFHE_FixedPoint, double>;