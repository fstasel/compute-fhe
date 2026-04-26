#include "include/CFHE_Test.h"
#include <computefhe/BaseALU.h>

#include <iostream>
using namespace std;
using namespace computefhe_test;

TestReport CFHE_Test::TestHalfAdder() {
    TestReport report;
    BinaryDigit ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    uint expected_sum = n1 ^ n2;
    uint expected_carry = n1 & n2;
    StartTimer();
    cfhe_base->GetALU()->HalfAdder(ct_n1, ct_n2, ct_result_sum,
                                   ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result =
        (result_sum == expected_sum && result_carry == expected_carry)
            ? TR_SUCCESS
            : TR_FAIL;
    PrintTestReport(report, n1, n2, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestHalfAdder_CP() {
    TestReport report;
    BinaryDigit result_sum, result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit pt_n2 = n2;
    uint expected_sum = n1 ^ n2;
    uint expected_carry = n1 & n2;
    StartTimer();
    cfhe_base->GetALU()->HalfAdder(ct_n1, pt_n2, result_sum, result_carry);
    report.delta_t = ReadTimer();
    uint sum = cfhe_base->DecryptBool(result_sum);
    uint carry = result_carry.is_ct ? cfhe_base->DecryptBool(result_carry)
                                    : result_carry.p;
    report.test_result =
        (sum == expected_sum && carry == expected_carry) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestFullAdder() {
    TestReport report;
    BinaryDigit ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetALU()->FullAdder(ct_n1, ct_n2, ct_n3, ct_result_sum,
                                   ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result =
        (result_sum == expected_sum && result_carry == expected_carry)
            ? TR_SUCCESS
            : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestFullAdder_CPP() {
    TestReport report;
    BinaryDigit result_sum, result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit pt_n2 = n2;
    BinaryDigit pt_n3 = n3;
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetALU()->FullAdder(ct_n1, pt_n2, pt_n3, result_sum,
                                   result_carry);
    report.delta_t = ReadTimer();
    uint sum = cfhe_base->DecryptBool(result_sum);
    uint carry = result_carry.is_ct ? cfhe_base->DecryptBool(result_carry)
                                    : result_carry.p;
    report.test_result =
        (sum == expected_sum && carry == expected_carry) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestFullAdder_CCP() {
    TestReport report;
    BinaryDigit ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit pt_n3 = n3;
    uint expected_sum = n1 ^ n2 ^ n3;
    uint expected_carry = (n1 & n2) | (n1 & n3) | (n2 & n3);
    StartTimer();
    cfhe_base->GetALU()->FullAdder(ct_n1, ct_n2, pt_n3, ct_result_sum,
                                   ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result =
        (result_sum == expected_sum && result_carry == expected_carry)
            ? TR_SUCCESS
            : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestXOR3() {
    TestReport report;
    BinaryDigit ct_result;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected = n1 ^ n2 ^ n3;
    StartTimer();
    ct_result = cfhe_base->GetALU()->Gate_XOR3(ct_n1, ct_n2, ct_n3);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestMulAdd() {
    TestReport report;
    BinaryDigit ct_result_sum, ct_result_carry;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected_sum = (n1 & n2) ^ n3;
    uint expected_carry = n1 & n2 & n3;
    StartTimer();
    ct_result_sum =
        cfhe_base->GetALU()->Gate_MulAdd(ct_n1, ct_n2, ct_n3, &ct_result_carry);
    report.delta_t = ReadTimer();
    uint result_sum = cfhe_base->DecryptBool(ct_result_sum);
    uint result_carry = cfhe_base->DecryptBool(ct_result_carry);
    report.test_result =
        (result_sum == expected_sum && result_carry == expected_carry)
            ? TR_SUCCESS
            : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result_sum + (result_carry << 1),
                    expected_sum + (expected_carry << 1));
    return report;
}

TestReport CFHE_Test::TestAdd(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->Add(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAdd(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PAdd(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    cfhe_base->GetALU()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->AddC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PAddC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->AddNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PAddNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestAddCNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    cfhe_base->GetALU()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->AddCNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPAddCNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + n2 + n3) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PAddCNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestSub(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->Sub(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSub(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->CPSub(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSub(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint pt_n1 = cfhe_base->GetConstantInt(n1, n_digits);
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PSub(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    cfhe_base->GetALU()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->SubC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->CPSubC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint pt_n1 = cfhe_base->GetConstantInt(n1, n_digits);
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PSubC(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->SubNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->CPSubNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint pt_n1 = cfhe_base->GetConstantInt(n1, n_digits);
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + 1)) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PSubNC(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestSubCNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    cfhe_base->GetALU()->SetCarry(cfhe_base->EncryptBool(n3, GetTestFresh()));
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->SubCNC(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestCPSubCNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->CPSubCNC(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestPSubCNC(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    uint n3 = CreateRandomNumber() % 2;
    uint carry_type = CreateRandomNumber() % 2;
    FixedPoint pt_n1 = cfhe_base->GetConstantInt(n1, n_digits);
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 + (UINT32_MAX - n2 + n3)) & ((1UL << n_digits) - 1);
    if (carry_type == 0) {
        cfhe_base->GetALU()->SetCarry(
            cfhe_base->EncryptBool(n3, GetTestFresh()));
    } else {
        cfhe_base->GetALU()->SetCarry(n3);
    }
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->PSubCNC(pt_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected);
    return report;
}

TestReport CFHE_Test::TestNeg(uint n_digits) {
    TestReport report;
    uint n = CreateRandomNumber();
    FixedPoint ct_n = cfhe_base->EncryptInt(n, n_digits, GetTestFresh());
    uint expected = (UINT32_MAX - n + 1) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->Neg(ct_n);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpNotEq(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 != n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpNotEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpNotEq(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 != n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpNotEq(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpEq(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 == n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpEq(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = (CreateRandomNumber() % 2 == 0) ? CreateRandomNumber() : n1;
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 == n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpEq(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLTEq_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLTEq_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLTEq_U(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGT_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGT_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGT_U(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGTEq_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGTEq_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGTEq_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGTEq_U(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLT_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLT_U(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLT_U(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLT_U(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLTEq(uint n_digits) {
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
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLTEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLTEq(uint n_digits) {
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 <= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLTEq(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGT(uint n_digits) {
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
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGT(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGT(uint n_digits) {
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 > n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGT(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpGTEq(uint n_digits) {
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
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGTEq(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpGTEq(uint n_digits) {
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 >= n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpGTEq(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestCmpLT(uint n_digits) {
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
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLT(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestPCmpLT(uint n_digits) {
    TestReport report;
    int64_t n1 = CreateRandomNumber();
    int64_t n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint pt_n2 = cfhe_base->GetConstantInt(n2, n_digits);
    int64_t bound = 1UL << n_digits;
    int64_t max_val = (1UL << (n_digits - 1)) - 1;
    n1 = (n1 > max_val) ? (n1 - bound) : n1;
    n2 = (n2 > max_val) ? (n2 - bound) : n2;
    uint expected = (n1 < n2) ? 1 : 0;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->CmpLT(ct_n1, pt_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestFullMul(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = n1 * n2;
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->FullMul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestMul(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber();
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected = (n1 * n2) & ((1UL << n_digits) - 1);
    StartTimer();
    FixedPoint ct_result = cfhe_base->GetALU()->Mul(ct_n1, ct_n2);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptInt(ct_result);
    report.test_result = (result == expected) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, result, expected);
    return report;
}

TestReport CFHE_Test::TestDivU(uint n_digits) {
    TestReport report;
    uint n1 = CreateRandomNumber();
    uint n2 = CreateRandomNumber() % (1UL << n_digits);
    while (n2 == 0) {
        n2 = CreateRandomNumber() % (1UL << n_digits);
    }
    FixedPoint ct_n1 = cfhe_base->EncryptInt(n1, n_digits, GetTestFresh());
    FixedPoint ct_n2 = cfhe_base->EncryptInt(n2, n_digits, GetTestFresh());
    uint expected_q = n1 / n2;
    uint expected_r = n1 % n2;
    FixedPoint ct_result_q;
    FixedPoint ct_result_r;
    StartTimer();
    cfhe_base->GetALU()->DivU(ct_n1, ct_n2, ct_result_q, ct_result_r);
    report.delta_t = ReadTimer();
    uint result_q = cfhe_base->DecryptInt(ct_result_q);
    uint result_r = cfhe_base->DecryptInt(ct_result_r);
    report.test_result = (result_q == expected_q && result_r == expected_r)
                             ? TR_SUCCESS
                             : TR_FAIL;
    PrintTestReport(report, n1, n2, result_q, expected_q);
    PrintTestReport(report, n1, n2, result_r, expected_r);
    return report;
}

TestReport CFHE_Test::TestMux() {
    TestReport report;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit ct_n3 = cfhe_base->EncryptBool(n3, GetTestFresh());
    uint expected_result = n1 ? n3 : n2;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->Gate_MUX(ct_n1, ct_n2, ct_n3);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected_result) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected_result);
    return report;
}

TestReport CFHE_Test::TestPMux() {
    TestReport report;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit ct_n2 = cfhe_base->EncryptBool(n2, GetTestFresh());
    BinaryDigit pt_n3 = n3;
    uint expected_result = n1 ? n3 : n2;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->Gate_MUX(ct_n1, ct_n2, pt_n3);
    report.delta_t = ReadTimer();
    uint result = cfhe_base->DecryptBool(ct_result);
    report.test_result = (result == expected_result) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected_result);
    return report;
}

TestReport CFHE_Test::TestPPMux() {
    TestReport report;
    uint n1 = CreateRandomNumber() % 2;
    uint n2 = CreateRandomNumber() % 2;
    uint n3 = CreateRandomNumber() % 2;
    BinaryDigit ct_n1 = cfhe_base->EncryptBool(n1, GetTestFresh());
    BinaryDigit pt_n2 = n2;
    BinaryDigit pt_n3 = n3;
    uint expected_result = n1 ? n3 : n2;
    StartTimer();
    BinaryDigit ct_result = cfhe_base->GetALU()->Gate_MUX(ct_n1, pt_n2, pt_n3);
    report.delta_t = ReadTimer();
    uint result =
        ct_result.is_ct ? cfhe_base->DecryptBool(ct_result) : ct_result.p;
    report.test_result = (result == expected_result) ? TR_SUCCESS : TR_FAIL;
    PrintTestReport(report, n1, n2, n3, result, expected_result);
    return report;
}