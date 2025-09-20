#include "BaseArithmeticsEngine.h"

BaseArithmeticsEngine::BaseArithmeticsEngine(ComputeFHE *cfhe) : cfhe_base(cfhe)
{
    ResetCarry();
}

BaseArithmeticsEngine::~BaseArithmeticsEngine()
{
}

LWECiphertext BaseArithmeticsEngine::GetCarry()
{
    return carry;
}

void BaseArithmeticsEngine::SetCarry(LWECiphertext value)
{
    carry = COPY_CT(value);
}

void BaseArithmeticsEngine::SetCarry()
{
    carry = GetConstantTrue();
}

void BaseArithmeticsEngine::ResetCarry()
{
    carry = GetConstantFalse();
}

LWECiphertext BaseArithmeticsEngine::GetConstantFalse()
{
    LWECiphertext constant_false = cfhe_base->GetBinFHEContext().EvalConstant(false);
    return COPY_CT(constant_false);
}

LWECiphertext BaseArithmeticsEngine::GetConstantTrue()
{
    LWECiphertext constant_true = cfhe_base->GetBinFHEContext().EvalConstant(true);
    return COPY_CT(constant_true);
}

FixedPoint BaseArithmeticsEngine::ToggleMSB(const FixedPoint &a)
{
    auto &cc = cfhe_base->GetBinFHEContext();
    FixedPoint t = FixedPoint(a);
    t.back() = cc.EvalNOT(t.back());
    return t;
}

TestReport BaseArithmeticsEngine::TestHalfAdder()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = cfhe_base->CreateRandomNumber() % 2;
    uint n2 = cfhe_base->CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, cfhe_base->GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, cfhe_base->GetTestFresh());
    uint expected_sum = n1 ^ n2;
    uint expected_carry = n1 & n2;
    cfhe_base->StartTimer();
    HalfAdder(ct_n1, ct_n2, ct_result_sum, ct_result_carry);
    report.delta_t = cfhe_base->ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry) ? TR_SUCCESS
                                                                                        : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport BaseArithmeticsEngine::TestFullAdder()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = cfhe_base->CreateRandomNumber() % 2;
    uint n2 = cfhe_base->CreateRandomNumber() % 2;
    uint n3 = cfhe_base->CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, cfhe_base->GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, cfhe_base->GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, cfhe_base->GetTestFresh());
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    cfhe_base->StartTimer();
    FullAdder(ct_n1, ct_n2, ct_n3, ct_result_sum, ct_result_carry);
    report.delta_t = cfhe_base->ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry) ? TR_SUCCESS
                                                                                        : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport BaseArithmeticsEngine::TestXOR3()
{
    TestReport report;
    LWECiphertext ct_result;
    uint n1 = cfhe_base->CreateRandomNumber() % 2;
    uint n2 = cfhe_base->CreateRandomNumber() % 2;
    uint n3 = cfhe_base->CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, cfhe_base->GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, cfhe_base->GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, cfhe_base->GetTestFresh());
    uint expected = n1 ^ n2 ^ n3;
    cfhe_base->StartTimer();
    ct_result = XOR3(ct_n1, ct_n2, ct_n3);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestMulAdd()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = cfhe_base->CreateRandomNumber() % 2;
    uint n2 = cfhe_base->CreateRandomNumber() % 2;
    uint n3 = cfhe_base->CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, cfhe_base->GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, cfhe_base->GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, cfhe_base->GetTestFresh());
    uint expected_sum = (n1 & n2) ^ n3;
    uint expected_carry = n1 & n2 & n3;
    cfhe_base->StartTimer();
    ct_result_sum = MulAdd(ct_n1, ct_n2, ct_n3, &ct_result_carry);
    report.delta_t = cfhe_base->ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry)
                             ? TR_SUCCESS
                             : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport BaseArithmeticsEngine::TestAdd(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = Add(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestAddC(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    uint n3 = cfhe_base->CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    SetCarry(cfhe_base->EncryptBool(n3, cfhe_base->GetTestFresh()));
    cfhe_base->StartTimer();
    FixedPoint ct_result = AddC(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestAddNC(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = AddNC(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestSub(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = Sub(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestSubC(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    uint n3 = cfhe_base->CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    SetCarry(cfhe_base->EncryptBool(n3, cfhe_base->GetTestFresh()));
    cfhe_base->StartTimer();
    FixedPoint ct_result = SubC(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestSubNC(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = SubNC(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestNeg(uint n_digits)
{
    TestReport report;
    uint n = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n = cfhe_base->EncryptInt(n, n_digits, cfhe_base->GetTestFresh());
    uint expected = (UINT32_MAX - n + 1) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = Neg(ct_n);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpNotEq(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = (cfhe_base->CreateRandomNumber() % 2 == 0) ? cfhe_base->CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 != n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpNotEq(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpEq(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = (cfhe_base->CreateRandomNumber() % 2 == 0) ? cfhe_base->CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 == n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpEq(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpLTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 <= n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpLTEq_U(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpGT_U(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 > n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpGT_U(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpGTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 >= n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpGTEq_U(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpLT_U(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 < n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpLT_U(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpLTEq(uint n_digits)
{
    TestReport report;
    int64_t n1 = cfhe_base->CreateRandomNumber();
    int64_t n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 <= n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpLTEq(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpGT(uint n_digits)
{
    TestReport report;
    int64_t n1 = cfhe_base->CreateRandomNumber();
    int64_t n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 > n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpGT(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpGTEq(uint n_digits)
{
    TestReport report;
    int64_t n1 = cfhe_base->CreateRandomNumber();
    int64_t n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 >= n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpGTEq(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestCmpLT(uint n_digits)
{
    TestReport report;
    int64_t n1 = cfhe_base->CreateRandomNumber();
    int64_t n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 < n2) ? 1 : 0;
    cfhe_base->StartTimer();
    LWECiphertext ct_result = CmpLT(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestFullMul(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = n1 * n2;
    cfhe_base->StartTimer();
    FixedPoint ct_result = FullMul(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport BaseArithmeticsEngine::TestMul(uint n_digits)
{
    TestReport report;
    uint n1 = cfhe_base->CreateRandomNumber();
    uint n2 = cfhe_base->CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, cfhe_base->GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, cfhe_base->GetTestFresh());
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    cfhe_base->StartTimer();
    FixedPoint ct_result = Mul(ct_n1, ct_n2);
    report.delta_t = cfhe_base->ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    cfhe_base->PrintTestReport(report, n1, n2, result, expected);
    return report;
}
