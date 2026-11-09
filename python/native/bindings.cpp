// SPDX-License-Identifier: MIT
#include <pybind11/pybind11.h>
#include <computefhe/ComputeFHE.h>

namespace py = pybind11;
using namespace computefhe;

// These low-level objects are private implementation details. Python owns the
// lifetime checks and retains the GIL for every call into the global backend.
namespace {
void require_context() {
    if (!cfhe_base) throw std::runtime_error("No active ComputeFHE context");
}

Einteger integer(uint64_t value, size_t bits, bool sign, bool encrypt) {
    require_context();
    if (bits < 1 || bits > 64) throw py::value_error("bits must be in [1, 64]");
    return Einteger(encrypt ? cfhe_base->EncryptInt(value, bits)
                            : cfhe_base->GetConstantInt(value, bits), sign);
}

template <class T> void bind_vector(py::module_ &m, const char *name) {
    py::class_<Evector<T>>(m, name)
        .def(py::init([](py::iterable values) {
            require_context();
            Evector<T> result;
            for (py::handle value : values) result.push_back(value.cast<T>());
            if (result.empty()) throw py::value_error("Vector must be nonempty");
            return result;
        }))
        .def("__len__", [](const Evector<T> &v) { return v.size(); })
        .def("get", [](Evector<T> &v, size_t i) {
            require_context();
            return T(v.at(i));
        })
        .def("set", [](Evector<T> &v, size_t i, const T &value) {
            require_context();
            v.at(i) = value;
        })
        .def("get_encrypted", [](Evector<T> &v, const Einteger &i) {
            require_context();
            return static_cast<T>(v[i]);
        })
        .def("set_encrypted", [](Evector<T> &v, const Einteger &i, const T &value) {
            require_context();
            v[i] = value;
        });
}

template <class T> T binary(const std::string &op, const T &a, const T &b) {
    require_context();
    if (op == "add") return a + b;
    if (op == "sub") return a - b;
    if (op == "mul") return a * b;
    throw py::value_error("Unknown arithmetic operation");
}

template <class T> Einteger compare(const std::string &op, const T &a, const T &b) {
    require_context();
    if (op == "eq") return a == b;
    if (op == "ne") return a != b;
    if (op == "lt") return a < b;
    if (op == "le") return a <= b;
    if (op == "gt") return a > b;
    if (op == "ge") return a >= b;
    throw py::value_error("Unknown comparison");
}

py::tuple unsigned_divmod(const Einteger &a, const Einteger &b) {
    require_context();
    if (a.isSigned() || b.isSigned()) {
        PyErr_SetString(PyExc_NotImplementedError,
                        "Signed division is not supported by ComputeFHE");
        throw py::error_already_set();
    }
    if (a.getSize() != b.getSize())
        throw py::value_error("Division operands must have matching widths");
    // DivU already produces both outputs. Return them from one native call.
    FixedPoint quotient, remainder;
    cfhe_base->GetALU()->DivU(a.getData(), b.getData(), quotient, remainder);
    return py::make_tuple(Einteger(quotient, false), Einteger(remainder, false));
}
}

PYBIND11_MODULE(_native, m) {
    m.doc() = "Private ComputeFHE bindings; use the public computefhe API";
    m.def("init", [](int parameter, bool optimized, bool simulation) {
        if (cfhe_base) throw std::runtime_error("A context is already active");
        if (parameter < 0 || parameter > 12) throw py::value_error("Invalid parameter");
        // Simulation does not need the expensive cryptographic key generation.
        Init(static_cast<CryptoContextParam>(parameter),
             optimized ? ALU_OPTIMIZED : ALU_STANDARD, !simulation, simulation);
        cfhe_base->setAutoEncryptMode(false);
    });
    m.def("finalize", &Finalize);
    py::class_<Einteger>(m, "Integer")
        .def_property_readonly("bits", &Einteger::getSize)
        .def_property_readonly("signed", &Einteger::isSigned);
    py::class_<Efixedpoint>(m, "Fixed")
        .def_property_readonly("bits", &Efixedpoint::getSize)
        .def_property_readonly("signed", &Efixedpoint::isSigned)
        .def_property_readonly("frac", &Efixedpoint::getFracSize);
    bind_vector<Einteger>(m, "IntegerVector");
    bind_vector<Efixedpoint>(m, "FixedVector");
    m.def("integer", &integer);
    m.def("fixed", [](uint64_t raw, size_t bits, size_t frac, bool sign, bool encrypt) {
        if (frac >= bits) throw py::value_error("frac must be smaller than bits");
        return Efixedpoint(integer(raw, bits, sign, encrypt).getData(), frac, sign);
    });
    m.def("decrypt_int", [](const Einteger &a) {
        require_context();
        return cfhe_base->DecryptInt(a.getData());
    });
    m.def("decrypt_fixed", [](const Efixedpoint &a) {
        require_context();
        return cfhe_base->DecryptInt(a.getData());
    });
    m.def("arithmetic", &binary<Einteger>);
    m.def("unsigned_divmod", &unsigned_divmod);
    m.def("fixed_arithmetic", &binary<Efixedpoint>);
    m.def("compare", &compare<Einteger>);
    m.def("fixed_compare", &compare<Efixedpoint>);
    m.def("bitwise", [](const std::string &op, const Einteger &a, const Einteger &b) {
        require_context();
        if (op == "and") return a & b;
        if (op == "or") return a | b;
        if (op == "xor") return a ^ b;
        throw py::value_error("Unknown bitwise operation");
    });
    m.def("invert", [](const Einteger &a) { require_context(); return ~a; });
    m.def("negate", [](const Einteger &a) { require_context(); return -a; });
    m.def("fixed_negate", [](const Efixedpoint &a) { require_context(); return -a; });
    m.def("shift", [](const Einteger &a, int amount, bool left) {
        require_context();
        if (amount < 0) throw py::value_error("negative shift count");
        return left ? a << amount : a >> amount;
    });
    m.def("cast", [](const Einteger &a, size_t bits, bool sign) {
        require_context();
        if (bits < 1 || bits > 64) throw py::value_error("bits must be in [1, 64]");
        return Einteger(Einteger::promote(a, bits), sign);
    });
    m.def("select", [](const Einteger &c, const Einteger &a, const Einteger &b) {
        require_context();
        if (c.getSize() != 1 || a.getSize() != b.getSize() || a.isSigned() != b.isSigned())
            throw py::value_error("select requires a boolean and matching value types");
        // The backend selects its third operand when s=1.
        // Python select(c, a, b) means c ? a : b.
        return Einteger(cfhe_base->GetALU()->Mux(c.getData()[0], b.getData(), a.getData()), a.isSigned());
    });
    m.def("fixed_select", [](const Einteger &c, const Efixedpoint &a, const Efixedpoint &b) {
        require_context();
        if (c.getSize() != 1 || a.getSize() != b.getSize() || a.isSigned() != b.isSigned() || a.getFracSize() != b.getFracSize())
            throw py::value_error("select requires a boolean and matching value types");
        return Efixedpoint(cfhe_base->GetALU()->Mux(c.getData()[0], b.getData(), a.getData()), a.getFracSize(), a.isSigned());
    });
}
