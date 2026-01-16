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

TestReport CFHE_Test::TestHalfAdder_CP()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    LWEPlaintext pt_result_carry;
    bool is_carry_ct = false;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWEPlaintext pt_n2 = n2;
    uint expected_sum = n1 ^ n2;
    uint expected_carry = n1 & n2;
    StartTimer();
    cfhe_base->GetArithmeticsEngine()->HalfAdder(ct_n1, pt_n2, ct_result_sum, ct_result_carry, pt_result_carry, is_carry_ct);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = is_carry_ct ? cfhe_base->DecryptBool(ct_result_carry) : pt_result_carry;
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

TestReport CFHE_Test::TestFullAdder_CPP()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    LWEPlaintext pt_result_carry;
    bool is_carry_ct = false;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWEPlaintext pt_n2 = n2;
    LWEPlaintext pt_n3 = n3;
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetArithmeticsEngine()->FullAdder(ct_n1, pt_n2, pt_n3, ct_result_sum, ct_result_carry, pt_result_carry, is_carry_ct);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = is_carry_ct ? cfhe_base->DecryptBool(ct_result_carry) : pt_result_carry;
    report.test_result = (result_sum == expected_sum && result_carry == expected_carry) ? TR_SUCCESS
                                                                                        : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestFullAdder_CCP()
{
    TestReport report;
    LWECiphertext ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    LWECiphertext ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    LWECiphertext ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    LWEPlaintext pt_n3 = n3;
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetArithmeticsEngine()->FullAdder(ct_n1, ct_n2, pt_n3, ct_result_sum, ct_result_carry);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Add(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAdd(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Add(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddC(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddCNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddCNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddCNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->AddCNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestSub(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Sub(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSub(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Sub(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSub(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    PFixedPoint pt_n1 = cfhe_base->uint2PFixedPoint(n1, n_digits);
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Sub(pt_n1, ct_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    PFixedPoint pt_n1 = cfhe_base->uint2PFixedPoint(n1, n_digits);
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubC(pt_n1, ct_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    PFixedPoint pt_n1 = cfhe_base->uint2PFixedPoint(n1, n_digits);
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubNC(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubCNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubCNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubCNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubCNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubCNC(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    PFixedPoint pt_n1 = cfhe_base->uint2PFixedPoint(n1, n_digits);
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0)
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    }
    else
    {
        cfhe_base->GetArithmeticsEngine()->SetCarry(n3);
    }
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->SubCNC(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestNeg(uint n_digits)
{
    TestReport report;
    uint n = CreateRandomNumber();
    CFixedPoint ct_n = cfhe_base->EncryptInt(n, n_digits, GetTestFresh());
    uint expected = (UINT32_MAX - n + 1) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Neg(ct_n);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 != n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpNotEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpNotEq(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 != n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpNotEq(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 == n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpEq(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 == n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpEq(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLTEq_U(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGT_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGT_U(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGTEq_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpGTEq_U(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLT_U(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    LWECiphertext ct_result = cfhe_base->GetArithmeticsEngine()->CmpLT_U(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = n1 * n2;
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->FullMul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPFullMul(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = n1 * n2;
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->FullMul(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPFullMulFast(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = n1 * n2;
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->FullMulFast(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestBoothsMul(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    int signed_result = (n1 & (1 << (n_digits - 1)) ? (long)n1 - (1UL << n_digits) : (long)n1);
    signed_result *= (n2 & (1 << (n_digits - 1)) ? (long)n2 - (1UL << n_digits) : (long)n2);
    uint expected = *(uint *)&signed_result & ((1UL << (n_digits << 1)) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->BoothsMul(ct_n1, pt_n2);
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
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    CFixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Mul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPMul(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->Mul(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPMulFast(uint n_digits)
{
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    CFixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    PFixedPoint pt_n2 = cfhe_base->uint2PFixedPoint(n2, n_digits);
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    StartTimer();
    CFixedPoint ct_result = cfhe_base->GetArithmeticsEngine()->MulFast(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}
