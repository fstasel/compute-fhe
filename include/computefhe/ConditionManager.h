/**
 * @file ConditionManager.h
 * @brief Manages conditional execution state and branch tracking for encrypted
 * operations.
 */

#pragma once
#include <computefhe/FixedPoint.h>
#include <stack>
#include <unordered_map>

using namespace std;

/**
 * @brief Encrypted conditional branching macro (FHE-compatible "if").
 *
 * This macro provides a high-level syntax for conditional logic on encrypted
 * data. Because FHE ciphertexts cannot be used in standard C++ control flow
 * statements without decryption, this macro uses a state machine
 * (ConditionManager) to execute logic and then multiplex the results.
 *
 * @important This macro is strictly intended for modifying **encrypted types**
 * (e.g., `Einteger`, `Efixedpoint`, `Euint8` etc). Ordinary, unencrypted C++
 * variables (like `int`, `float`, or `bool`) should not be modified inside an
 * `Eif` block.
 *
 * Nested `Eif` and `else` statements are fully supported.
 *
 * Usage example:
 * @code
 * Eif(encrypted_bool) {
 *     // Logic executed if encrypted_bool is true
 * } else {
 *     // optional
 * }
 * @endcode
 *
 * @param cond An encrypted boolean representing the condition.
 */
#define Eif(cond)                                                              \
    for (ConditionManager _m((cond).getData()[0]); !_m.done();                 \
         _m.next_state())                                                      \
        if (_m.if_state())

namespace computefhe {
    /**
     * @struct ConditionalVar
     * @brief Internal tracking structure for encrypted variables in conditional blocks.
     *
     * Stores the previous, 'if', and 'else' branch values of a variable to facilitate
     * homomorphic multiplexing at the end of a conditional scope.
     */
    typedef struct {
        FixedPoint prev_value;
        FixedPoint if_value;
        FixedPoint else_value;
        FixedPoint *data;
    } ConditionalVar;

    /**
     * @class ConditionManager
     * @brief Manages conditional execution state and variable multiplexing.
     *
     * This class tracks which encrypted variables are modified within an Eif block
     * and ensures that their final values are correctly computed based on the
     * encrypted condition.
     */
    class ConditionManager {
      private:
        int state;
        BinaryDigit cond;
        unordered_map<void *, ConditionalVar> registry;

      public:
        ConditionManager(const BinaryDigit &condition);
        ~ConditionManager();
        static void register_variable(void *var_instance, FixedPoint *data);
        static void unregister_variable(void *var_instance);
        void next_state();
        bool done();
        bool if_state();

        static bool conditional_mode();
    };
} // namespace computefhe
