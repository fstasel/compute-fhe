#pragma once

#include <computefhe/Efixedpoint.h>
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
        Eitem(Evector<T> &vec, const Einteger &idx);
        Eitem(Evector<T> &vec, const size_t idx);
        operator T() const;
        const T &operator=(const T &value);

        T operator+(const T &b) const;
        T operator+(U b) const;
        T operator-(const T &b) const;
        T operator-(U b) const;
        T operator*(const T &b) const;
        T operator*(U b) const;
        T operator/(const T &b) const;
        T operator/(U b) const;
        T operator%(const T &b) const;
        T operator%(U b) const;
        T operator&(const T &b) const;
        T operator&(U b) const;
        T operator|(const T &b) const;
        T operator|(U b) const;
        T operator^(const T &b) const;
        T operator^(U b) const;

        Einteger operator==(const T &b) const;
        Einteger operator==(U b) const;
        Einteger operator!=(const T &b) const;
        Einteger operator!=(U b) const;
        Einteger operator>(const T &b) const;
        Einteger operator>(U b) const;
        Einteger operator>=(const T &b) const;
        Einteger operator>=(U b) const;
        Einteger operator<(const T &b) const;
        Einteger operator<(U b) const;
        Einteger operator<=(const T &b) const;
        Einteger operator<=(U b) const;

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
        Eitem<T, U> &operator/=(const T &b);
        Eitem<T, U> &operator/=(U b);
        Eitem<T, U> &operator%=(const T &b);
        Eitem<T, U> &operator%=(U b);
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

        Eitem<Einteger, uint64_t> operator[](const Einteger &index) {
            return Eitem<Einteger, uint64_t>(
                reinterpret_cast<Evector<Einteger> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<Einteger, uint64_t>(
                reinterpret_cast<Evector<Einteger> &>(*this), (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        T &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <> class Evector<Einteger> : public std::vector<Einteger> {
      public:
        using std::vector<Einteger>::vector;
        using std::vector<Einteger>::operator[];

        Eitem<Einteger, uint64_t> operator[](const Einteger &index) {
            return Eitem<Einteger, uint64_t>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<Einteger, uint64_t>(*this, (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        Einteger &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <> class Evector<Efixedpoint> : public std::vector<Efixedpoint> {
      public:
        using std::vector<Efixedpoint>::vector;
        using std::vector<Efixedpoint>::operator[];

        Eitem<Efixedpoint, double> operator[](const Einteger &index) {
            return Eitem<Efixedpoint, double>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<Efixedpoint, double>(*this, (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        Efixedpoint &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    template <size_t N, size_t F, bool S>
    class Evector<EFix<N, F, S>> : public std::vector<EFix<N, F, S>> {
      public:
        using std::vector<EFix<N, F, S>>::vector;
        using std::vector<EFix<N, F, S>>::operator[];

        Eitem<Efixedpoint, double> operator[](const Einteger &index) {
            return Eitem<Efixedpoint, double>(
                reinterpret_cast<Evector<Efixedpoint> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<Efixedpoint, double>(
                reinterpret_cast<Evector<Efixedpoint> &>(*this), (size_t)index);
        }

        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        EFix<N, F, S> &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };
} // namespace computefhe
