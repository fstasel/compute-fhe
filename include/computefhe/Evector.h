#pragma once

#include <computefhe/CFHE_FixedPoint.h>
#include <type_traits>
#include <vector>

namespace computefhe {

    template <typename T> class Evector;

    template <typename T, typename U> class Eitem {
      protected:
        Evector<T> &data;
        FixedPoint index;
        size_t p_index;
        bool encrypted_index;

      public:
        Eitem(Evector<T> &vec, const CFHE_Integer &idx);
        Eitem(Evector<T> &vec, const size_t idx);
        operator T() const;
        const T &operator=(const T &value);

        T operator+(const T &b) const;
        T operator+(U b) const;
        T operator-(const T &b) const;
        T operator-(U b) const;
        T operator*(const T &b) const;
        T operator*(U b) const;
        T operator&(const T &b) const;
        T operator&(U b) const;
        T operator|(const T &b) const;
        T operator|(U b) const;
        T operator^(const T &b) const;
        T operator^(U b) const;

        CFHE_Integer operator==(const T &b) const;
        CFHE_Integer operator==(U b) const;
        CFHE_Integer operator!=(const T &b) const;
        CFHE_Integer operator!=(U b) const;
        CFHE_Integer operator>(const T &b) const;
        CFHE_Integer operator>(U b) const;
        CFHE_Integer operator>=(const T &b) const;
        CFHE_Integer operator>=(U b) const;
        CFHE_Integer operator<(const T &b) const;
        CFHE_Integer operator<(U b) const;
        CFHE_Integer operator<=(const T &b) const;
        CFHE_Integer operator<=(U b) const;

        T operator&&(const T &b) const;
        T operator&&(U b) const;
        T operator||(const T &b) const;
        T operator||(U b) const;

        T operator<<(int b) const;
        T operator>>(int b) const;

        Eitem<T, U> &operator+=(const T &b);
        Eitem<T, U> &operator+=(U b);
        Eitem<T, U> &operator-=(const T &b);
        Eitem<T, U> &operator-=(U b);
        Eitem<T, U> &operator*=(const T &b);
        Eitem<T, U> &operator*=(U b);
        Eitem<T, U> &operator&=(const T &b);
        Eitem<T, U> &operator&=(U b);
        Eitem<T, U> &operator|=(const T &b);
        Eitem<T, U> &operator|=(U b);
        Eitem<T, U> &operator^=(const T &b);
        Eitem<T, U> &operator^=(U b);
        Eitem<T, U> &operator<<=(int b);
        Eitem<T, U> &operator>>=(int b);

        T operator!() const;
        T operator~() const;
        T operator-() const;
        T operator++();
        T operator++(int);
        T operator--();
        T operator--(int);
    };

    template <typename T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];

        Eitem<CFHE_Integer, uint64_t> operator[](const CFHE_Integer &index) {
            return Eitem<CFHE_Integer, uint64_t>(
                reinterpret_cast<Evector<CFHE_Integer> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<CFHE_Integer, uint64_t>(
                reinterpret_cast<Evector<CFHE_Integer> &>(*this),
                (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        T &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <> class Evector<CFHE_Integer> : public std::vector<CFHE_Integer> {
      public:
        using std::vector<CFHE_Integer>::vector;
        using std::vector<CFHE_Integer>::operator[];

        Eitem<CFHE_Integer, uint64_t> operator[](const CFHE_Integer &index) {
            return Eitem<CFHE_Integer, uint64_t>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<CFHE_Integer, uint64_t>(*this, (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        CFHE_Integer &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <>
    class Evector<CFHE_FixedPoint> : public std::vector<CFHE_FixedPoint> {
      public:
        using std::vector<CFHE_FixedPoint>::vector;
        using std::vector<CFHE_FixedPoint>::operator[];

        Eitem<CFHE_FixedPoint, double> operator[](const CFHE_Integer &index) {
            return Eitem<CFHE_FixedPoint, double>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<CFHE_FixedPoint, double>(*this, (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        CFHE_FixedPoint &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <size_t N, size_t F, bool S>
    class Evector<EFix<N, F, S>> : public std::vector<EFix<N, F, S>> {
      public:
        using std::vector<EFix<N, F, S>>::vector;
        using std::vector<EFix<N, F, S>>::operator[];

        Eitem<CFHE_FixedPoint, double> operator[](const CFHE_Integer &index) {
            return Eitem<CFHE_FixedPoint, double>(
                reinterpret_cast<Evector<CFHE_FixedPoint> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<CFHE_FixedPoint, double>(
                reinterpret_cast<Evector<CFHE_FixedPoint> &>(*this),
                (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        EFix<N, F, S> &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };
} // namespace computefhe
