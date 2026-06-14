/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file Evector.h
 * @brief Provides vector containers with support for oblivious, encrypted
 * indexing.
 */

#pragma once
#include <computefhe/Efixedpoint.h>
#include <type_traits>
#include <vector>

namespace computefhe {

    /**
     * @class Evector
     * @brief A vector container that supports element access via encrypted
     * indices.
     *
     * This class inherits from std::vector and provides overloaded operator[]
     * to allow for "Oblivious Array Access". When an encrypted index is used,
     * it returns an Eitem proxy.
     */
    template <typename T> class Evector;

    /**
     * @class Eitem
     * @brief Proxy object for accessing and modifying elements in an Evector
     * using encrypted indices.
     *
     * Eitem acts as a bridge between the vector and encrypted logic. When an
     * operation is performed on an Eitem initialized with an encrypted index,
     * the library performs the operation across all elements of the underlying
     * vector using multiplexers (MUX) to ensure the secret index is not leaked.
     *
     * @tparam T The encrypted type stored in the vector (i.e., Einteger).
     * @tparam U The corresponding plaintext type for constant operations.
     */
    template <typename T, typename U> class Eitem {
      protected:
        Evector<T> &data; ///< Reference to the parent vector.
        FixedPoint index; ///< The encrypted index value.
        size_t p_index; ///< Plaintext index (used if encrypted_index is false).
        bool encrypted_index; ///< Flag indicating if the index is encrypted.

      public:
        /** @brief Constructs a proxy item using an encrypted index. */
        Eitem(Evector<T> &vec, const Einteger &idx);
        /** @brief Constructs a proxy item using a plaintext index. */
        Eitem(Evector<T> &vec, const size_t idx);

        /** @brief Implicit conversion to the underlying encrypted type T. */
        operator T() const;

        /** @brief Implicit conversion to any type constructible from T (e.g.,
         * derived types like Euint64). */
        template <typename V,
                  typename = std::enable_if_t<std::is_constructible_v<V, T> &&
                                              !std::is_same_v<V, T>>>
        operator V() const {
            return V(operator T());
        }

        /** @brief Assignment operator: conditionally updates vector elements
         * based on the index. */
        const T &operator=(const T &value);

        /** @brief Assignment operator from a plaintext value: converts to T
         * using vector element metadata and then updates elements. */
        const T &operator=(U value);

        /** @name Arithmetic Operators */
        ///@{
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
        ///@}

        /** @name Bitwise Logic Operators */
        ///@{
        T operator&(const T &b) const;
        T operator&(U b) const;
        T operator|(const T &b) const;
        T operator|(U b) const;
        T operator^(const T &b) const;
        T operator^(U b) const;
        ///@}

        /** @name Comparison Operators */
        ///@{
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
        ///@}

        /** @name Logical Operators */
        ///@{
        T operator&&(const T &b) const;
        T operator&&(U b) const;
        T operator||(const T &b) const;
        T operator||(U b) const;
        ///@}

        /** @name Shift Operators */
        ///@{
        T operator<<(int b) const;
        T operator>>(int b) const;
        ///@}

        /** @name Compound Assignment Operators */
        ///@{
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
        ///@}

        /** @name Unary and Inc/Dec Operators */
        ///@{
        T operator!() const;
        T operator~() const;
        T operator-() const;
        T operator++();
        T operator++(int);
        T operator--();
        T operator--(int);
        ///@}

        /** @brief Stream insertion operator to handle direct printing of proxy
         * items. */
        friend std::ostream &operator<<(std::ostream &out,
                                        const Eitem<T, U> &item) {
            return out << static_cast<T>(item);
        }
    };

    /**
     * @brief General template for Evector.
     */
    template <typename T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];

        /**
         * @brief Access element using an encrypted index.
         * @return An Eitem proxy representing the element at the secret
         * position.
         */
        Eitem<Einteger, uint64_t> operator[](const Einteger &index) {
            return Eitem<Einteger, uint64_t>(
                reinterpret_cast<Evector<Einteger> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<Einteger, uint64_t>(
                reinterpret_cast<Evector<Einteger> &>(*this), (size_t)index);
        }

        /**
         * @brief Access element using a plaintext integral index.
         * Overloads standard std::vector access to return a direct reference.
         */
        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        T &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    /**
     * @brief Specialization of Evector for Einteger.
     */
    template <> class Evector<Einteger> : public std::vector<Einteger> {
      public:
        using std::vector<Einteger>::vector;
        using std::vector<Einteger>::operator[];

        /**
         * @brief Access element using an encrypted index.
         * @return An Eitem proxy representing the encrypted integer.
         */
        Eitem<Einteger, uint64_t> operator[](const Einteger &index) {
            return Eitem<Einteger, uint64_t>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<Einteger, uint64_t>(*this, (size_t)index);
        }

        /** @brief Access element using a plaintext index. */
        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        Einteger &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    /**
     * @brief Specialization of Evector for Efixedpoint.
     */
    template <> class Evector<Efixedpoint> : public std::vector<Efixedpoint> {
      public:
        using std::vector<Efixedpoint>::vector;
        using std::vector<Efixedpoint>::operator[];

        /**
         * @brief Access element using an encrypted index.
         * @return An Eitem proxy representing the encrypted fixed-point value.
         */
        Eitem<Efixedpoint, double> operator[](const Einteger &index) {
            return Eitem<Efixedpoint, double>(*this, index);
            // TODO: Use below in client-mode only
            return Eitem<Efixedpoint, double>(*this, (size_t)index);
        }

        /** @brief Access element using a plaintext index. */
        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        Efixedpoint &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };

    /**
     * @brief Specialization of Evector for templated EFix types.
     */
    template <size_t N, size_t F, bool S>
    class Evector<EFix<N, F, S>> : public std::vector<EFix<N, F, S>> {
      public:
        using std::vector<EFix<N, F, S>>::vector;
        using std::vector<EFix<N, F, S>>::operator[];

        /**
         * @brief Access element using an encrypted index.
         * @return An Eitem proxy representing the fixed-precision value.
         */
        Eitem<Efixedpoint, double> operator[](const Einteger &index) {
            return Eitem<Efixedpoint, double>(
                reinterpret_cast<Evector<Efixedpoint> &>(*this), index);
            // TODO: Use below in client-mode only
            return Eitem<Efixedpoint, double>(
                reinterpret_cast<Evector<Efixedpoint> &>(*this), (size_t)index);
        }

        /** @brief Access element using a plaintext index. */
        template <typename Integral,
                  typename = std::enable_if_t<std::is_integral_v<Integral>>>
        EFix<N, F, S> &operator[](Integral idx) {
            return this->at(static_cast<size_t>(idx));
        }
    };
} // namespace computefhe
