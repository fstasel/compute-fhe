#include "CFHE_Test.h"
#include "BaseArithmeticsEngine.h"

#include <iostream>
using namespace std;

TestReport CFHE_Test::TestHalfAdder()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    uint expected_sum = n1 ^ n2;
    uint expected_carry = n1 & n2;
    StartTimer();
    cfhe_base->GetArithmeticsEngine()->HalfAdder(ct_n1, ct_n2, ct_result_sum, ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry) ? TR_SUCCESS
                                                                                        : TR_FAIL;
    PrintTestReport(report, n1, n2, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestFullAdder()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetArithmeticsEngine()->FullAdder(ct_n1, ct_n2, ct_n3, ct_result_sum, ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry) ? TR_SUCCESS
                                                                                        : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestXOR3()
{
    TestReport report;
    LWECiphertext ct_result;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected = n1 ^ n2 ^ n3;
    StartTimer();
    ct_result = cfhe_base->GetArithmeticsEngine()->XOR3(ct_n1, ct_n2, ct_n3);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestMulAdd()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    LWECiphertext ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected_sum = (n1 & n2) ^ n3;
    uint expected_carry = n1 & n2 & n3;
    StartTimer();
    ct_result_sum = cfhe_base->GetArithmeticsEngine()->MulAdd(ct_n1, ct_n2, ct_n3, &ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry)
                             ? TR_SUCCESS
                             : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                               expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestAdd(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Add(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestSub(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Sub(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestNeg(uint n_digits)
{
    TestReport report;
    uint n = CreateRandomNumber();
    FixedPoint ct_n = cfhe_base->EncryptInt(n, n_digits, GetTestFresh());
    uint expected = (UINT32_MAX - n + 1) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Neg(ct_n);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpNotEq(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 != n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpNotEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpEq(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 == n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGT_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLT_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLTEq(uint n_digits)
{
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLTEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGT(uint n_digits)
{
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGT(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGTEq(uint n_digits)
{
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGTEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLT(uint n_digits)
{
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLT(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestFullMul(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = n1 * n2;
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->FullMul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestMul(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Mul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}
