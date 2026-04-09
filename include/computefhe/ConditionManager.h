#pragma once
#include <computefhe/ComputeFHE.h>

using namespace std;

#define Eif(cond)                                                              \
    for (ConditionManager _m((cond).getData()[0]); !_m.done();                 \
         _m.next_state())                                                      \
        if (_m.if_state())

namespace computefhe {
    typedef struct {
        FixedPoint prev_value;
        FixedPoint if_value;
        FixedPoint else_value;
        FixedPoint *data;
    } ConditionalVar;

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
