#pragma once

#include <computefhe/CFHE_Integer.h>
#include <computefhe/ComputeFHE.h>
#include <vector>

namespace computefhe {

    template <class T> class Eitem;

    template <class T> class Evector : public std::vector<T> {
      public:
        using std::vector<T>::vector;
        using std::vector<T>::operator[];
        template <class I> Eitem<T> operator[](const I &index);
        T &operator[](const int idx);
    };

    template <class T> class Eitem {
      protected:
        Evector<T> &data;
        FixedPoint index;
        size_t p_index;
        bool encrypted_index;

      public:
        template <class I> Eitem(Evector<T> &vec, const I &idx);
        Eitem(Evector<T> &vec, const size_t idx);
        operator T() const;
        const T &operator=(const T &value);
    };

// Helper macros for Eitem operator declarations
#define DECLARE_E_ITEM_BINARY_FRIEND(NAME, OP, RET)                            \
    friend RET operator OP(const Eitem<NAME> &a, const CFHE_Integer &b);       \
    friend RET operator OP(const Eitem<NAME> &a, uint64_t b);

#define DECLARE_E_ITEM_BINARY_GLOBAL(NAME, OP, RET)                            \
    RET operator OP(const Eitem<NAME> &a, const CFHE_Integer &b);              \
    RET operator OP(const Eitem<NAME> &a, uint64_t b);

#define DECLARE_E_ITEM_SHIFT_FRIEND(NAME, OP)                                  \
    friend NAME operator OP(const Eitem<NAME> &a, int b);

#define DECLARE_E_ITEM_SHIFT_GLOBAL(NAME, OP)                                  \
    NAME operator OP(const Eitem<NAME> &a, int b);

#define DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, OP)                                 \
    friend Eitem<NAME> operator OP(Eitem<NAME> a, const CFHE_Integer & b);     \
    friend Eitem<NAME> operator OP(Eitem<NAME> a, uint64_t b);

#define DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, OP)                                 \
    Eitem<NAME> operator OP(Eitem<NAME> a, const CFHE_Integer & b);            \
    Eitem<NAME> operator OP(Eitem<NAME> a, uint64_t b);

#define DECLARE_E_ITEM_SHIFT_ASSIGN_FRIEND(NAME, OP)                           \
    friend Eitem<NAME> operator OP(Eitem<NAME> a, int b);

#define DECLARE_E_ITEM_SHIFT_ASSIGN_GLOBAL(NAME, OP)                           \
    Eitem<NAME> operator OP(Eitem<NAME> a, int b);

#define DECLARE_E_ITEM_UNARY_FRIEND(NAME, OP, RET)                             \
    friend RET operator OP(const Eitem<NAME> &a);

#define DECLARE_E_ITEM_UNARY_GLOBAL(NAME, OP, RET)                             \
    RET operator OP(const Eitem<NAME> &a);

#define DECLARE_E_ITEM_INC_DEC_FRIEND(NAME, OP)                                \
    friend NAME operator OP(Eitem<NAME> a);                                    \
    friend NAME operator OP(Eitem<NAME> a, int);

#define DECLARE_E_ITEM_INC_DEC_GLOBAL(NAME, OP)                                \
    NAME operator OP(Eitem<NAME> a);                                           \
    NAME operator OP(Eitem<NAME> a, int);

#define DECLARE_E_ITEM_ALL_FRIENDS(NAME)                                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, +, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, -, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, *, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, &, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, |, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, ^, NAME)                                \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, ==, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, !=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, >, CFHE_Integer)                        \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, >=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, <, CFHE_Integer)                        \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, <=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, &&, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_FRIEND(NAME, ||, CFHE_Integer)                       \
    DECLARE_E_ITEM_SHIFT_FRIEND(NAME, <<)                                      \
    DECLARE_E_ITEM_SHIFT_FRIEND(NAME, >>)                                      \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, +=)                                     \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, -=)                                     \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, *=)                                     \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, &=)                                     \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, |=)                                     \
    DECLARE_E_ITEM_ASSIGN_FRIEND(NAME, ^=)                                     \
    DECLARE_E_ITEM_SHIFT_ASSIGN_FRIEND(NAME, <<=)                              \
    DECLARE_E_ITEM_SHIFT_ASSIGN_FRIEND(NAME, >>=)                              \
    DECLARE_E_ITEM_UNARY_FRIEND(NAME, !, CFHE_Integer)                         \
    DECLARE_E_ITEM_UNARY_FRIEND(NAME, ~, CFHE_Integer)                         \
    DECLARE_E_ITEM_UNARY_FRIEND(NAME, -, NAME)                                 \
    DECLARE_E_ITEM_INC_DEC_FRIEND(NAME, ++)                                    \
    DECLARE_E_ITEM_INC_DEC_FRIEND(NAME, --)

#define DECLARE_E_ITEM_ALL_GLOBALS(NAME)                                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, +, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, -, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, *, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, &, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, |, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, ^, NAME)                                \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, ==, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, !=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, >, CFHE_Integer)                        \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, >=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, <, CFHE_Integer)                        \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, <=, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, &&, CFHE_Integer)                       \
    DECLARE_E_ITEM_BINARY_GLOBAL(NAME, ||, CFHE_Integer)                       \
    DECLARE_E_ITEM_SHIFT_GLOBAL(NAME, <<)                                      \
    DECLARE_E_ITEM_SHIFT_GLOBAL(NAME, >>)                                      \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, +=)                                     \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, -=)                                     \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, *=)                                     \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, &=)                                     \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, |=)                                     \
    DECLARE_E_ITEM_ASSIGN_GLOBAL(NAME, ^=)                                     \
    DECLARE_E_ITEM_SHIFT_ASSIGN_GLOBAL(NAME, <<=)                              \
    DECLARE_E_ITEM_SHIFT_ASSIGN_GLOBAL(NAME, >>=)                              \
    DECLARE_E_ITEM_UNARY_GLOBAL(NAME, !, CFHE_Integer)                         \
    DECLARE_E_ITEM_UNARY_GLOBAL(NAME, ~, CFHE_Integer)                         \
    DECLARE_E_ITEM_UNARY_GLOBAL(NAME, -, NAME)                                 \
    DECLARE_E_ITEM_INC_DEC_GLOBAL(NAME, ++)                                    \
    DECLARE_E_ITEM_INC_DEC_GLOBAL(NAME, --)

#define DECLARE_E_TYPE(NAME, TYPE, BITS, SIGNED)                               \
    class NAME : public CFHE_Integer {                                         \
      public:                                                                  \
        NAME(TYPE d = 0);                                                      \
        NAME(const CFHE_Integer &other);                                       \
        DECLARE_E_ITEM_ALL_FRIENDS(NAME)                                       \
    };                                                                         \
    DECLARE_E_ITEM_ALL_GLOBALS(NAME)

    DECLARE_E_TYPE(Ebool, bool, 1, false)
    DECLARE_E_TYPE(Eint8, int8_t, 8, true)
    DECLARE_E_TYPE(Euint8, uint8_t, 8, false)
    DECLARE_E_TYPE(Eint16, int16_t, 16, true)
    DECLARE_E_TYPE(Euint16, uint16_t, 16, false)
    DECLARE_E_TYPE(Eint32, int32_t, 32, true)
    DECLARE_E_TYPE(Euint32, uint32_t, 32, false)
    DECLARE_E_TYPE(Eint64, int64_t, 64, true)
    DECLARE_E_TYPE(Euint64, uint64_t, 64, false)

#undef DECLARE_E_ITEM_BINARY_FRIEND
#undef DECLARE_E_ITEM_BINARY_GLOBAL
#undef DECLARE_E_ITEM_SHIFT_FRIEND
#undef DECLARE_E_ITEM_SHIFT_GLOBAL
#undef DECLARE_E_ITEM_ASSIGN_FRIEND
#undef DECLARE_E_ITEM_ASSIGN_GLOBAL
#undef DECLARE_E_ITEM_SHIFT_ASSIGN_FRIEND
#undef DECLARE_E_ITEM_SHIFT_ASSIGN_GLOBAL
#undef DECLARE_E_ITEM_UNARY_FRIEND
#undef DECLARE_E_ITEM_UNARY_GLOBAL
#undef DECLARE_E_ITEM_INC_DEC_FRIEND
#undef DECLARE_E_ITEM_INC_DEC_GLOBAL
#undef DECLARE_E_ITEM_ALL_FRIENDS
#undef DECLARE_E_ITEM_ALL_GLOBALS
#undef DECLARE_E_TYPE

} // namespace computefhe
