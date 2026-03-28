#include <computefhe/CFHE_Integer.h>
#include <computefhe/Evector.h>

using namespace computefhe;

template <class T>
template <class U, bool S>
T &Evector<T>::operator[](const CFHE_Integer<U, S> &index) {
    // Client-mode only
    return (
        *this)[static_cast<size_t>(const_cast<CFHE_Integer<U, S> &>(index))];
}

template <class T>
template <class U, bool S>
const T &Evector<T>::operator[](const CFHE_Integer<U, S> &index) const {
    // Client-mode only
    return (
        *this)[static_cast<size_t>(const_cast<CFHE_Integer<U, S> &>(index))];
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
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Ebool &);                                                        \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Euint8 &);                                                       \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Euint16 &);                                                      \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Euint32 &);                                                      \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Euint64 &);                                                      \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Eint8 &);                                                        \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Eint16 &);                                                       \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Eint32 &);                                                       \
    template CFHE_Integer<T, S> &Evector<CFHE_Integer<T, S>>::operator[](      \
        const Eint64 &);                                                       \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Ebool &) const;              \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Euint8 &) const;             \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Euint16 &) const;            \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Euint32 &) const;            \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Euint64 &) const;            \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Eint8 &) const;              \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Eint16 &) const;             \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Eint32 &) const;             \
    template const CFHE_Integer<T, S> &                                        \
    Evector<CFHE_Integer<T, S>>::operator[](const Eint64 &) const;

CFHE_TYPES(INSTANTIATE_EVECTOR)
