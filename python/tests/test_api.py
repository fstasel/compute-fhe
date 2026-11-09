import os
import threading
import unittest
from unittest.mock import patch

from computefhe import _native

from computefhe import (
    Context, Parameters, EncryptedInt, EncryptedFixed, EncryptedVector,
    Ebool, Eint8, Euint8, Eint16, Euint64, Eint64, select,
)


class SimulationTests(unittest.TestCase):
    def setUp(self):
        self.ctx = Context(simulation=True, parameters=Parameters.TOY)
        self.addCleanup(self.ctx.close)

    def test_arithmetic_and_public_constants(self):
        a, b = Eint8(12), Eint8(5)
        for result, expected in [
            (a + b, 17), (a - b, 7), (a * b, 60), (2 + a, 14),
            (20 - a, 8), (3 * b, 15), (-a, -12), (Eint8(127) + 1, -128),
            (Euint8(255) + 1, 0), (a + -3, 9),
        ]:
            self.assertEqual(result.decrypt(), expected)

    def test_signed_division_is_unsupported(self):
        for encrypted in [False, True]:
            for value in [-128, -7, 0, 7, 127]:
                a = Eint8(value, encrypted=encrypted)
                for b in [0, 3, Eint8(3, encrypted=encrypted)]:
                    for operation in [lambda: a // b, lambda: a % b,
                                      lambda: divmod(a, b)]:
                        with self.subTest(value=value, encrypted=encrypted):
                            with self.assertRaisesRegex(NotImplementedError, "Signed division"):
                                operation()
                for operation in [lambda: 20 // a, lambda: 20 % a]:
                    with self.assertRaisesRegex(NotImplementedError, "Signed division"):
                        operation()
        # The private binding also rejects signed operands rather than treating
        # their bit patterns as unsigned values.
        a, b = Eint8(7), Euint8(3)
        with self.assertRaises(NotImplementedError):
            _native.unsigned_divmod(a._value, b._value)
        with self.assertRaises(NotImplementedError):
            _native.unsigned_divmod(b._value, a._value)

    def test_unsigned_division(self):
        for encrypt_a in [False, True]:
            for encrypt_b in [False, True]:
                a = Euint8(255, encrypted=encrypt_a)
                b = Euint8(7, encrypted=encrypt_b)
                q, r = divmod(a, b)
                self.assertEqual((q.decrypt(), r.decrypt()), (36, 3))
                self.assertEqual((a // b).decrypt(), 36)
                self.assertEqual((a % b).decrypt(), 3)
        self.assertEqual((Euint8(255) // 7).decrypt(), 36)
        self.assertEqual((Euint8(255) % 7).decrypt(), 3)
        self.assertEqual((255 // Euint8(7)).decrypt(), 36)
        self.assertEqual((255 % Euint8(7)).decrypt(), 3)
        for operation in [lambda: Euint8(3) // 0, lambda: Euint8(3) % 0,
                          lambda: divmod(Euint8(3), 0)]:
            with self.assertRaises(ZeroDivisionError):
                operation()

    def test_division_uses_one_native_call(self):
        a, b = Euint8(255), Euint8(7)
        for operation, expected in [(lambda: a // b, 36), (lambda: a % b, 3),
                                    (lambda: divmod(a, b), (36, 3))]:
            # Count calls while still executing the actual native backend.
            with patch.object(_native, "unsigned_divmod", wraps=_native.unsigned_divmod) as native_call:
                result = operation()
                actual = (tuple(x.decrypt() for x in result) if isinstance(result, tuple)
                          else result.decrypt())
                self.assertEqual(actual, expected)
                self.assertEqual(native_call.call_count, 1)

    def test_comparisons_and_selection(self):
        a, b = Eint8(-3), Eint8(5)
        for result, expected in [(a < b, 1), (a <= -3, 1), (b > a, 1),
                                 (a >= b, 0), (a == -3, 1), (a != b, 1)]:
            self.assertEqual(result.bits, 1)
            self.assertEqual(result.decrypt(), expected)
        self.assertEqual(select(a > b, a, b).decrypt(), 5)
        self.assertEqual(select(Ebool(1), 2, b).decrypt(), 2)
        self.assertEqual(select(Ebool(0), a, 7).decrypt(), 7)
        with self.assertRaises(TypeError):
            select(a, a, b)

    def test_no_implicit_decryption(self):
        a = Eint8(42)
        for convert in [bool, int, float]:
            with self.assertRaises(TypeError):
                convert(a)
        with self.assertRaises(TypeError):
            bool(a == 42)
        self.assertNotIn("42", repr(a))
        with self.assertRaises(TypeError):
            hash(a)

    def test_bitwise_shifts_and_casts(self):
        a = Euint8(10)
        for result, expected in [(a & 6, 2), (a | 5, 15), (a ^ 3, 9),
                                 (~a, 245), (a << 2, 40), (a >> 2, 2),
                                 (a << 100, 0), (Eint8(-8) >> 2, -2),
                                 (Eint8(-8) >> 100, -1)]:
            self.assertEqual(result.decrypt(), expected)
        self.assertEqual(Eint8(-2).cast(bits=16).decrypt(), -2)
        self.assertEqual(Euint8(255).cast(signed=True).decrypt(), -1)
        with self.assertRaises(ValueError):
            a << -1

    def test_input_validation_and_large_values(self):
        self.assertEqual(Euint64(2**64 - 1).decrypt(), 2**64 - 1)
        self.assertEqual(Eint64(-(2**63)).decrypt(), -(2**63))
        for factory, value in [(Eint8, 128), (Eint8, -129), (Euint8, -1),
                               (Euint64, 2**64), (Ebool, 2)]:
            with self.assertRaises(OverflowError):
                factory(value)
        for bits in [0, 65, -1]:
            with self.assertRaises(ValueError):
                EncryptedInt(0, bits=bits)
        with self.assertRaises(TypeError):
            Eint8(1) + Eint16(1)
        with self.assertRaises(TypeError):
            Eint8(1) + 1.5

    def test_fixed_point(self):
        a = EncryptedFixed(1.5, bits=16, frac=8)
        b = EncryptedFixed(2.25, bits=16, frac=8)
        self.assertEqual((a + b).decrypt(), 3.75)
        self.assertEqual((b - a).decrypt(), 0.75)
        self.assertEqual((a * b).decrypt(), 3.375)
        self.assertEqual((-a).decrypt(), -1.5)
        self.assertEqual((2.0 + a).decrypt(), 3.5)
        self.assertEqual((4.0 - a).decrypt(), 2.5)
        self.assertEqual(select(a < b, a, b).decrypt(), 1.5)
        self.assertEqual(EncryptedFixed(-1.1, bits=8, frac=4).decrypt(), -1.0625)
        for value in [float("nan"), float("inf")]:
            with self.assertRaises(ValueError):
                EncryptedFixed(value)
        with self.assertRaises(ValueError):
            EncryptedFixed(1, bits=8, frac=8)

    def test_native_vector_simulation(self):
        v = EncryptedVector([Eint8(10), Eint8(20), Eint8(30)])
        self.assertEqual(v[Euint8(1)].decrypt(), 20)
        v[Euint8(1)] = 25
        self.assertEqual([x.decrypt() for x in v], [10, 25, 30])
        self.assertEqual(v[Euint8(7)].decrypt(), 0)
        self.assertEqual(v[Eint8(-1)].decrypt(), 0)
        v[Euint8(7)] = 99
        self.assertEqual(v[-1].decrypt(), 30)
        with self.assertRaises(IndexError):
            v[7]
        # Native Eitem zero-extends short indices and truncates long ones.
        self.assertEqual(v[Ebool(1)].decrypt(), 25)
        self.assertEqual(v[Euint8(4)].decrypt(), 10)
        v[Euint8(5)] = 26
        self.assertEqual([x.decrypt() for x in v], [10, 26, 30])
        with self.assertRaises(TypeError):
            EncryptedVector([Eint8(1), Eint16(2)])

    def test_native_fixed_vector_simulation(self):
        v = EncryptedVector([EncryptedFixed(1.5, bits=16, frac=8),
                             EncryptedFixed(-2.25, bits=16, frac=8)])
        self.assertEqual(v[Euint8(1)].decrypt(), -2.25)
        v[Ebool(0)] = -0.75
        self.assertEqual([x.decrypt() for x in v], [-0.75, -2.25])
        self.assertEqual(v[Euint8(2)].decrypt(), -0.75)

    def test_context_lifetime(self):
        with self.assertRaises(RuntimeError):
            Context(simulation=True)
        old = Eint8(12)
        self.ctx.close()
        self.ctx.close()
        with self.assertRaises(RuntimeError):
            old.decrypt()
        with Context(simulation=True, parameters=Parameters.TOY):
            with self.assertRaises(RuntimeError):
                old + Eint8(1)

    def test_thread_restriction(self):
        a = Eint8(1)
        errors = []
        def worker():
            try:
                a.decrypt()
            except RuntimeError as exc:
                errors.append(str(exc))
        thread = threading.Thread(target=worker)
        thread.start()
        thread.join()
        self.assertEqual(len(errors), 1)


class ContextTests(unittest.TestCase):
    def test_four_bit_reference_model(self):
        # All pairs exercise sign boundaries, overflow, and division on both ALUs.
        for optimized in [False, True]:
            with Context(simulation=True, optimized=optimized, parameters=Parameters.TOY):
                for signed in [False, True]:
                    values = range(-8, 8) if signed else range(16)
                    def wrap(value):
                        return (value + 8) % 16 - 8 if signed else value % 16
                    for a in values:
                        for b in values:
                            x = EncryptedInt(a, bits=4, signed=signed)
                            y = EncryptedInt(b, bits=4, signed=signed)
                            self.assertEqual((x + y).decrypt(), wrap(a + b))
                            self.assertEqual((x - y).decrypt(), wrap(a - b))
                            self.assertEqual((x * y).decrypt(), wrap(a * b))
                            self.assertEqual((x < y).decrypt(), int(a < b))
                            self.assertEqual(select(x < y, x, y).decrypt(), min(a, b))
                            if b and not signed:
                                q, r = divmod(x, y)
                                self.assertEqual(q.decrypt(), wrap(a // b))
                                self.assertEqual(r.decrypt(), a % b)

    def test_explicit_initialization(self):
        with self.assertRaises(RuntimeError):
            Eint8(1)

    def test_exception_cleanup(self):
        with self.assertRaisesRegex(ValueError, "test"):
            with Context(simulation=True, parameters=Parameters.TOY):
                raise ValueError("test")
        with Context(simulation=True, parameters=Parameters.TOY):
            self.assertEqual(Eint8(1).decrypt(), 1)


@unittest.skipUnless(os.getenv("COMPUTEFHE_TEST_CRYPTO") == "1", "set COMPUTEFHE_TEST_CRYPTO=1")
class CryptoTests(unittest.TestCase):
    def test_real_encrypted_evaluation(self):
        with Context(parameters=Parameters.TOY):
            a, b = EncryptedInt(3, bits=4), EncryptedInt(2, bits=4)
            self.assertEqual((a + b).decrypt(), 5)
            self.assertEqual((a * b).decrypt(), 6)
            self.assertEqual(select(a > b, a, b).decrypt(), 3)
            self.assertEqual((a + 1).decrypt(), 4)
            with self.assertRaises(NotImplementedError):
                divmod(EncryptedInt(-3, bits=4), b)
            dividend = EncryptedInt(7, bits=4, signed=False)
            divisor = EncryptedInt(2, bits=4, signed=False)
            q, r = divmod(dividend, divisor)
            self.assertEqual((q.decrypt(), r.decrypt()), (3, 1))
            self.assertEqual((dividend // 2).decrypt(), 3)
            self.assertEqual((dividend % 2).decrypt(), 1)
            self.assertEqual((7 // divisor).decrypt(), 3)
            self.assertEqual((7 % divisor).decrypt(), 1)
            values = EncryptedVector([Eint8(10), Eint8(20), Eint8(30)])
            self.assertEqual(values[Euint8(1)].decrypt(), 20)
            values[Euint8(1)] = 25
            self.assertEqual([x.decrypt() for x in values], [10, 25, 30])
            self.assertEqual(values[Euint8(4)].decrypt(), 10)
            f = EncryptedFixed(1.5, bits=8, frac=4)
            self.assertEqual((f + 0.25).decrypt(), 1.75)
            self.assertEqual((f * 2).decrypt(), 3.0)


if __name__ == "__main__":
    unittest.main()
