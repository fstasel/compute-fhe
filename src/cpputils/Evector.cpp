#include <cmath>
#include <computefhe/CFHE_Integer.h>
#include <computefhe/Evector.h>

using namespace computefhe;

template <class T>
template <class I>
Eitem<T> Evector<T>::operator[](I &index) {
    return Eitem<T>(*this, index);
    // TODO: Use below in client-mode only
    return Eitem<T>(*this, (uint64_t)index);
}

template <class T>
template <class I>
Eitem<T>::Eitem(Evector<T> &vec, const I &idx) : data(vec) {
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
        return T(
            CFHE_Integer(result, data[0].isSigned(), n, data[0].isSigned()));
    }
    return data[p_index];
}

template <class T> const T &Eitem<T>::operator=(const T &value) {
    if (encrypted_index) {
        size_t n = data[0].getData().size();
        for (size_t i = 0; i < data.size(); ++i) {
            // TODO: optimize this by using ciphertext-plaintext comparison
            LWECiphertext c = cfhe_base->GetArithmeticsEngine()->CmpEq(
                index, cfhe_base->GetConstantInt(i, index.size()));
            FixedPoint &target_fp = const_cast<FixedPoint &>(data[i].getData());
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
    X(Ebool)                                                                   \
    X(Euint8)                                                                  \
    X(Euint16)                                                                 \
    X(Euint32)                                                                 \
    X(Euint64)                                                                 \
    X(Eint8)                                                                   \
    X(Eint16)                                                                  \
    X(Eint32)                                                                  \
    X(Eint64)

#define INSTANTIATE_EVECTOR(T)                                                 \
    template class Evector<T>;                                                 \
    template Eitem<T> Evector<T>::operator[](Ebool &);                         \
    template Eitem<T> Evector<T>::operator[](Euint8 &);                        \
    template Eitem<T> Evector<T>::operator[](Euint16 &);                       \
    template Eitem<T> Evector<T>::operator[](Euint32 &);                       \
    template Eitem<T> Evector<T>::operator[](Euint64 &);                       \
    template Eitem<T> Evector<T>::operator[](Eint8 &);                         \
    template Eitem<T> Evector<T>::operator[](Eint16 &);                        \
    template Eitem<T> Evector<T>::operator[](Eint32 &);                        \
    template Eitem<T> Evector<T>::operator[](Eint64 &);                        \
    template class Eitem<T>;                                                   \
    template Eitem<T>::Eitem(Evector<T> &, const Ebool &);                     \
    template Eitem<T>::Eitem(Evector<T> &, const Euint8 &);                    \
    template Eitem<T>::Eitem(Evector<T> &, const Euint16 &);                   \
    template Eitem<T>::Eitem(Evector<T> &, const Euint32 &);                   \
    template Eitem<T>::Eitem(Evector<T> &, const Euint64 &);                   \
    template Eitem<T>::Eitem(Evector<T> &, const Eint8 &);                     \
    template Eitem<T>::Eitem(Evector<T> &, const Eint16 &);                    \
    template Eitem<T>::Eitem(Evector<T> &, const Eint32 &);                    \
    template Eitem<T>::Eitem(Evector<T> &, const Eint64 &);

CFHE_TYPES(INSTANTIATE_EVECTOR)
