#include <cmath>
#include <computefhe/CFHE_Integer.h>
#include <computefhe/Evector.h>

using namespace computefhe;

template <class T>
template <class U, bool S>
Eitem<T> Evector<T>::operator[](CFHE_Integer<U, S> &index) {
    return Eitem<T>(*this, index);
    // TODO: Use below in client-mode only
    return Eitem<T>(*this, (U)index);
}

template <class T>
template <class U, bool S>
Eitem<T>::Eitem(Evector<T> &vec, const CFHE_Integer<U, S> &idx) : data(vec) {
    size_t n = vec.size();
    size_t bit_size =
        (n > 1) ? static_cast<size_t>(std::ceil(std::log2(n))) : 1;
    index = FixedPoint(bit_size);
    FixedPoint &fp = const_cast<CFHE_Integer<U, S> &>(idx).getData();
    for (size_t j = 0; j < bit_size; ++j) {
        if (j < fp.size())
            index[j] = fp[j];
        else
            index[j] = cfhe_base->GetArithmeticsEngine()->GetConstantFalse();
    }
    p_index = 0;
    encrypted_index = true;
}

template <class T>
Eitem<T>::Eitem(Evector<T> &vec, const size_t idx)
    : data(vec), p_index(idx), encrypted_index(false) {
    // empty
}

template <class T> Eitem<T>::operator T() {
    if (encrypted_index) {
        // TODO: optimize this by using ciphertext-plaintext comparison
        LWECiphertext c = cfhe_base->GetArithmeticsEngine()->CmpEq(
            index, cfhe_base->GetConstantInt(0, index.size()));
        size_t n = data[0].getData().size();
        FixedPoint result(n);

        for (size_t d = 0; d < n; ++d) {
            result[d] = cfhe_base->GetArithmeticsEngine()->Gate_AND(
                c, data[0].getData()[d]);
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
        return T(result, data[0].getIsSigned());
    }
    return data[p_index];
}

template <class T> template <class K> Eitem<T>::operator K() {
    return (K)(T)(*this);
}

template <class T> const T &Eitem<T>::operator=(const T &value) {
    if (encrypted_index) {
        size_t n = data[0].getData().size();
        for (size_t i = 0; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            LWECiphertext c = cfhe_base->GetArithmeticsEngine()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            FixedPoint &target_fp = const_cast<T &>(data[i]).getData();
            for (size_t d = 0; d < n; ++d) {
                LWECiphertext v = const_cast<T &>(value).getData()[d];
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

#define INSTANTIATE_EVECTOR(T, S)                                              \
    template class Evector<CFHE_Integer<T, S>>;                                \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Ebool &);                          \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Euint8 &);                         \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Euint16 &);                        \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Euint32 &);                        \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Euint64 &);                        \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Eint8 &);                          \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Eint16 &);                         \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Eint32 &);                         \
    template Eitem<CFHE_Integer<T, S>>                                         \
    Evector<CFHE_Integer<T, S>>::operator[](Eint64 &);                         \
    template class Eitem<CFHE_Integer<T, S>>;                                  \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Ebool &);                  \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Euint8 &);                 \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Euint16 &);                \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Euint32 &);                \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Euint64 &);                \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Eint8 &);                  \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Eint16 &);                 \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Eint32 &);                 \
    template Eitem<CFHE_Integer<T, S>>::Eitem(Evector<CFHE_Integer<T, S>> &,   \
                                              const Eint64 &);                 \
    template Eitem<CFHE_Integer<T, S>>::operator T();

CFHE_TYPES(INSTANTIATE_EVECTOR)
