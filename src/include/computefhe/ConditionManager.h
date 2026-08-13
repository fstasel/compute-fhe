/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file ConditionManager.h
 * @brief Manages conditional execution state, branch tracking, and homomorphic
 * multiplexing for encrypted operations.
 */

#pragma once
#include <computefhe/FixedPoint.h>
#include <stack>
#include <unordered_map>

using namespace std;

/**
 * @brief Encrypted conditional branching macro (FHE-compatible "if").
 *
 * Provides C-style syntactic sugar for conditional control flow over encrypted
 * data without decrypting ciphertexts or leaking comparison outcomes to the
 * server.
 *
 * ### Execution Mechanism
 * The macro expands into a `for` loop that uses a `ConditionManager` state
 * machine to execute **both** branches sequentially:
 * 1. **Iteration 1 (`if` branch):** `_m.if_state()` evaluates to `true`;
 * updates are tracked in the `if` context.
 * 2. **Iteration 2 (`else` branch):** `_m.if_state()` evaluates to `false`;
 * updates are tracked in the `else` context.
 * 3. **Scope Exit:** The loop terminates, triggering the `ConditionManager`
 * destructor to perform homomorphic multiplexing.
 *
 * @important This macro is strictly intended for modifying **encrypted types**
 * (e.g., `Einteger`, `Efixedpoint`, `Euint8`). Standard C++ primitive types
 * (such as raw `int`, `float`, or `bool`) must not be modified inside an `Eif`
 * block.
 *
 * ### Nested Conditionals
 * Nested `Eif` / `else` structures are fully supported. Stack-allocated
 * `ConditionManager` instances naturally cascade into chained homomorphic
 * multiplexers.
 *
 * Usage example:
 * @code
 * Eif(encrypted_bool) {
 *     a = b + 5;
 * } else {
 *     a = c * 2;
 * }
 * @endcode
 *
 * @param cond An encrypted boolean (`BinaryDigit`) representing the condition.
 */
#define Eif(cond)                                                              \
    for (ConditionManager _m((cond).getData()[0]); !_m.done();                 \
         _m.next_state())                                                      \
        if (_m.if_state())

namespace computefhe {
    /**
     * @struct ConditionalVar
     * @brief Internal tracking structure for encrypted variables in conditional
     * blocks.
     *
     * Stores the original (pre-condition), 'if'-branch, and 'else'-branch
     * states of a variable to enable final homomorphic multiplexing.
     */
    typedef struct {
        FixedPoint prev_value;
        FixedPoint if_value;
        FixedPoint else_value;
        FixedPoint *data;
    } ConditionalVar;

    /**
     * @class ConditionManager
     * @brief Manages state tracking, branch evaluation, and homomorphic multiplexing.
     *
     * In Fully Homomorphic Encryption (FHE), standard branch jumping is
     * impossible without decrypting data. `ConditionManager` addresses this by
     * evaluating both branch paths in plaintext execution flow while
     * maintaining encrypted isolation.
     *
     * ### Key Responsibilities:
     * - **State Tracking:** Intercepts assignments to encrypted variables
     * (`_sync_var()`) during branch evaluation and registers original, `if`,
     * and `else` state values.
     * - **Homomorphic Multiplexing:** Upon loop termination, the destructor
     * computes the final encrypted result for all modified variables
     * via homomorphic multiplexing:
     *   `out = MUX(cond, val_if, val_else)`
     * - **Zero-Knowledge Security:** The server executes all code paths
     * identically, ensuring the underlying comparison outcome remains entirely
     * encrypted throughout.
     * - **Composability:** Scoped lifecycle rules automatically compose nested
     *   conditional trees into sequential chains of multiplexer gates.
     */
    class ConditionManager {
      private:
        int state;
        BinaryDigit cond;
        unordered_map<void *, ConditionalVar> registry;

      public:
        /**
         * @brief Constructs a ConditionManager for a given encrypted condition.
         * @param condition Encrypted boolean condition bit governing the
         * branch.
         */
        ConditionManager(const BinaryDigit &condition);

        /**
         * @brief Destructor that performs homomorphic multiplexing on
         * registered variables. Combines `if` and `else` branch results using
         * FHE logic operations.
         */
        ~ConditionManager();

        static void register_variable(void *var_instance, FixedPoint *data);
        static void unregister_variable(void *var_instance);

        /**
         * @brief Advances the internal state machine from the `if` branch to
         * the `else` branch.
         */
        void next_state();

        /**
         * @brief Checks if both `if` and `else` evaluation passes are complete.
         * @return `true` if loop execution should terminate, `false` otherwise.
         */
        bool done();

        /**
         * @brief Returns the condition status for the preprocessor `if`
         * statement.
         * @return `true` during the `if` pass (iteration 1), `false` during the
         * `else` pass (iteration 2).
         */
        bool if_state();

        /**
         * @brief Indicates whether execution is currently inside an active
         * `Eif` block.
         */
        static bool conditional_mode();
    };
} // namespace computefhe
