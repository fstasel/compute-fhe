#include <computefhe/ComputeFHE.h>
#include <computefhe/ConditionManager.h>

using namespace computefhe;

namespace computefhe {
    extern ComputeFHE *cfhe_base;
    static stack<ConditionManager *> conditional_stack;
} // namespace computefhe

ConditionManager::ConditionManager(const BinaryDigit &condition)
    : state(0), cond(condition) {
    conditional_stack.push(this);
}

ConditionManager::~ConditionManager() {
    conditional_stack.pop();
    for (auto it = registry.begin(); it != registry.end(); it++) {
        if (!conditional_stack.empty()) {
            register_variable(it->first, &it->second.prev_value);
        }
        *it->second.data = cfhe_base->GetALU()->Mux(cond, it->second.else_value,
                                                    it->second.if_value);
        if (!conditional_stack.empty()) {
            register_variable(it->first, it->second.data);
        }
    }
}

void ConditionManager::register_variable(void *var_instance, FixedPoint *data) {
    ConditionManager *manager = conditional_stack.top();
    int state = manager->state;
    size_t sz = (*data).size();
    auto it = manager->registry.find(var_instance);

    if (it == manager->registry.end()) {
        FixedPoint prev_value(sz), if_value(sz), else_value(sz);
        for (size_t i = 0; i < sz; i++) {
            prev_value[i] = (BinaryDigit &)(*data)[i];
            if_value[i] = (BinaryDigit &)(*data)[i];
            else_value[i] = (BinaryDigit &)(*data)[i];
        }
        manager->registry.insert(
            {var_instance, {prev_value, if_value, else_value, data}});
    } else {
        it->second.data = data;
        for (size_t i = 0; i < sz; i++) {
            if (state == 0) {
                it->second.if_value[i] = (BinaryDigit &)(*data)[i];
            } else {
                it->second.else_value[i] = (BinaryDigit &)(*data)[i];
            }
        }
    }
}

void ConditionManager::unregister_variable(void *var_instance) {
    ConditionManager *manager = conditional_stack.top();
    auto it = manager->registry.find(var_instance);
    if (it != manager->registry.end()) {
        manager->registry.erase(it);
    }
}

void ConditionManager::next_state() {
    state++;
    if (state == 1) {
        for (auto it = registry.begin(); it != registry.end(); it++) {
            *it->second.data = it->second.else_value;
        }
    }
}

bool ConditionManager::done() { return state > 1; }

bool ConditionManager::if_state() { return state == 0; }

bool ConditionManager::conditional_mode() { return !conditional_stack.empty(); }
