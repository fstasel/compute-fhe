#pragma once

#include "ComputeFHE.h"
#include "BaseArithmeticsEngine.h"
#include "SimConstants.h"

using namespace lbcrypto;

class ComputeFHE;

class BaseAESimulator : public BaseArithmeticsEngine
{
protected:
  uint num_bs = 0;
  uint num_not = 0;
  uint num_andor = 0;
  uint num_xorxnor = 0;
  uint num_xor3 = 0;
  uint num_maj = 0;
  uint num_ma = 0;
  uint num_mac = 0;
  uint num_ds = 0;
  uint num_mux = 0;

  vector<double> bs_time;
  vector<double> bs_stdev;

  void init_error();

  long double get_error_andor();
  long double get_error_xorxnor();
  long double get_error_xor3();
  long double get_error_maj();
  long double get_error_ma();
  long double get_error_mac();
  long double get_error_ds();
  long double get_error_mux();

  long double error_andor;
  long double error_xorxnor;
  long double error_xor3;
  long double error_maj;
  long double error_ma;
  long double error_mac;
  long double error_ds;
  long double error_mux;

public:
  static LWECiphertext dummy_ct;
  static CFixedPoint dummy_cfixedpoint;

  BaseAESimulator(ComputeFHE *cfhe);

  void SetCarry();
  void ResetCarry();

  void PrintStats();
  void ResetStats();
  int GetLog2Error();

  // Abstracts
  virtual void HalfAdder() = 0;
  virtual void HalfAdder(const LWEPlaintext &b, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
  virtual void HalfSubtractor() = 0;
  virtual void HalfSubtractor(const LWEPlaintext &a, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
  virtual void FullAdder() = 0;
  virtual void FullAdder(const LWEPlaintext &b, const LWEPlaintext &c, LWEPlaintext &carry_out_pt, bool &is_carry_ct) = 0;
  virtual void FullAdder(const LWEPlaintext &c) = 0;

  virtual void XOR3() = 0;
  virtual void MulAdd(bool carry_out) = 0;
  virtual void DigitSum() = 0;

  virtual size_t Add_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out) = 0;
  virtual size_t Sub_CtCt_FixedPoint(const size_t n_bits, const bool &carry_in, const bool &carry_out) = 0;
  virtual size_t Add_CtPt_FixedPoint(const PFixedPoint &b, const bool &carry_in, const bool &carry_out) = 0;
  virtual size_t Sub_PtCt_FixedPoint(const PFixedPoint &a, const bool &carry_in, const bool &carry_out) = 0;

  virtual size_t Neg_Ct_FixedPoint(const size_t n_bits) = 0;

  virtual void CmpNotEq_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual void CmpEq_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual void CmpLTEq_U_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual void CmpGT_U_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual void CmpNotEq_CtPt_FixedPoint(const PFixedPoint &b) = 0;
  virtual void CmpEq_CtPt_FixedPoint(const PFixedPoint &b) = 0;
  virtual void CmpLTEq_U_CtPt_FixedPoint(const PFixedPoint &b) = 0;
  virtual void CmpGT_U_CtPt_FixedPoint(const PFixedPoint &b) = 0;

  virtual size_t FullMul_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual size_t FullMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;
  virtual size_t FullMulFast_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;
  virtual size_t BoothsMul_CtPt_FixedPoint(const size_t n_bits, const PFixedPoint &b) = 0;

  virtual size_t Mul_CtCt_FixedPoint(const size_t n_bits) = 0;
  virtual size_t Mul_CtPt_FixedPoint(const PFixedPoint &b) = 0;
  virtual size_t MulFast_CtPt_FixedPoint(const PFixedPoint &b) = 0;

  virtual void Mux_CCC() = 0;
  virtual void Mux_CCP(LWEPlaintext b) = 0;
  virtual void Mux_CPP(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct) = 0;

  // Wrappers
  void HalfAdder(ConstLWECiphertext &a, ConstLWECiphertext &b,
                 LWECiphertext &sum, LWECiphertext &carry_out);
  void HalfAdder(ConstLWECiphertext &a, const LWEPlaintext &b,
                 LWECiphertext &sum, LWECiphertext &carry_out_ct,
                 LWEPlaintext &carry_out_pt, bool &is_carry_ct);

  void HalfSubtractor(ConstLWECiphertext &a, ConstLWECiphertext &b,
                      LWECiphertext &sum, LWECiphertext &carry_out);
  void HalfSubtractor(const LWEPlaintext &a, ConstLWECiphertext &b,
                      LWECiphertext &sum, LWECiphertext &carry_out_ct,
                      LWEPlaintext &carry_out_pt, bool &is_carry_ct);

  void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c,
                 LWECiphertext &sum, LWECiphertext &carry_out);
  void FullAdder(ConstLWECiphertext &a, const LWEPlaintext &b, const LWEPlaintext &c,
                 LWECiphertext &sum, LWECiphertext &carry_out_ct,
                 LWEPlaintext &carry_out_pt, bool &is_carry_ct);
  void FullAdder(ConstLWECiphertext &a, ConstLWECiphertext &b, const LWEPlaintext &c,
                 LWECiphertext &sum, LWECiphertext &carry_out);

  LWECiphertext XOR3(ConstLWECiphertext &a, ConstLWECiphertext &b, ConstLWECiphertext &c);
  LWECiphertext MulAdd(ConstLWECiphertext &m, ConstLWECiphertext &a, ConstLWECiphertext &b,
                       LWECiphertext *carry_out = nullptr);
  LWECiphertext DigitSum(ConstLWECiphertext &e1, ConstLWECiphertext &e0, ConstLWECiphertext &s0);

  CFixedPoint Add_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                  const bool &carry_in, const bool &carry_out);
  CFixedPoint Sub_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b,
                                  const bool &carry_in, const bool &carry_out);
  CFixedPoint Add_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b,
                                  const bool &carry_in, const bool &carry_out);
  CFixedPoint Sub_PtCt_FixedPoint(const PFixedPoint &a, const CFixedPoint &b,
                                  const bool &carry_in, const bool &carry_out);

  CFixedPoint Neg_Ct_FixedPoint(const CFixedPoint &a);

  LWECiphertext CmpNotEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  LWECiphertext CmpEq_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  LWECiphertext CmpLTEq_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  LWECiphertext CmpGT_U_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  LWECiphertext CmpNotEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  LWECiphertext CmpEq_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  LWECiphertext CmpLTEq_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  LWECiphertext CmpGT_U_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

  CFixedPoint FullMul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  CFixedPoint FullMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  CFixedPoint FullMulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  CFixedPoint BoothsMul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

  CFixedPoint Mul_CtCt_FixedPoint(const CFixedPoint &a, const CFixedPoint &b);
  CFixedPoint Mul_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);
  CFixedPoint MulFast_CtPt_FixedPoint(const CFixedPoint &a, const PFixedPoint &b);

  LWECiphertext Mux_CCC(LWECiphertext s, LWECiphertext a, LWECiphertext b);
  LWECiphertext Mux_CCP(LWECiphertext s, LWECiphertext a, LWEPlaintext b);
  void Mux_CPP(LWECiphertext s, LWEPlaintext a, LWEPlaintext b,
               LWECiphertext &out_ct, LWEPlaintext &out_pt, bool &is_out_ct);

  size_t SimAdd(const size_t n_bits);
  size_t SimAddC(const size_t n_bits);
  size_t SimAddNC(const size_t n_bits);
  size_t SimAddCNC(const size_t n_bits);

  size_t SimSub(const size_t n_bits);
  size_t SimSubC(const size_t n_bits);
  size_t SimSubNC(const size_t n_bits);
  size_t SimSubCNC(const size_t n_bits);

  size_t SimAdd(const PFixedPoint &b);
  size_t SimAddC(const PFixedPoint &b);
  size_t SimAddNC(const PFixedPoint &b);
  size_t SimAddCNC(const PFixedPoint &b);

  size_t SimSub(const int a, const PFixedPoint &b);
  size_t SimSub(const PFixedPoint &a);
  size_t SimSubC(const int a, const PFixedPoint &b);
  size_t SimSubC(const PFixedPoint &a);
  size_t SimSubNC(const int a, const PFixedPoint &b);
  size_t SimSubNC(const PFixedPoint &a);
  size_t SimSubCNC(const int a, const PFixedPoint &b);
  size_t SimSubCNC(const PFixedPoint &a);

  void SimCmpNotEq(const size_t n_bits);
  void SimCmpNotEq(const PFixedPoint &b);

  void SimCmpEq(const size_t n_bits);
  void SimCmpEq(const PFixedPoint &b);

  void SimCmpLTEq_U(const size_t n_bits);
  void SimCmpLTEq_U(const int a, const PFixedPoint &b);
  void SimCmpLTEq_U(const PFixedPoint &a);

  void SimCmpGT_U(const size_t n_bits);
  void SimCmpGT_U(const int a, const PFixedPoint &b);
  void SimCmpGT_U(const PFixedPoint &a);

  void SimCmpGTEq_U(const size_t n_bits);
  void SimCmpGTEq_U(const int a, const PFixedPoint &b);
  void SimCmpGTEq_U(const PFixedPoint &a);

  void SimCmpLT_U(const size_t n_bits);
  void SimCmpLT_U(const int a, const PFixedPoint &b);
  void SimCmpLT_U(const PFixedPoint &a);

  void SimCmpLTEq(const size_t n_bits);
  void SimCmpLTEq(const int a, const PFixedPoint &b);
  void SimCmpLTEq(const PFixedPoint &a);

  void SimCmpGT(const size_t n_bits);
  void SimCmpGT(const int a, const PFixedPoint &b);
  void SimCmpGT(const PFixedPoint &a);

  void SimCmpGTEq(const size_t n_bits);
  void SimCmpGTEq(const int a, const PFixedPoint &b);
  void SimCmpGTEq(const PFixedPoint &a);

  void SimCmpLT(const size_t n_bits);
  void SimCmpLT(const int a, const PFixedPoint &b);
  void SimCmpLT(const PFixedPoint &a);

  size_t SimFullMul(const size_t n_bits);
  size_t SimFullMul(const size_t n_bits, const PFixedPoint &b);
  size_t SimFullMulFast(const size_t n_bits, const PFixedPoint &b);
  size_t SimBoothsMul(const size_t n_bits, const PFixedPoint &b);

  size_t SimMul(const size_t n_bits);
  size_t SimMul(const PFixedPoint &b);
  size_t SimMulFast(const PFixedPoint &b);

  size_t SimToggleMSB(const size_t n_bits);
  size_t SimNeg(const size_t n_bits);
  size_t SimNot(const size_t n_bits);

  void SimMux();
  void SimMux(LWEPlaintext b);
  void SimMux(int s, LWEPlaintext a);
  void SimMux(LWEPlaintext a, LWEPlaintext b, LWEPlaintext &out_pt, bool &is_out_ct);

  size_t SimMux(const size_t n_bits);
  size_t SimMux(const PFixedPoint b);
  size_t SimMux(int s, const PFixedPoint a);

  // Overrides
  using BaseArithmeticsEngine::Mux;
  using BaseArithmeticsEngine::Not;
  using BaseArithmeticsEngine::PXOR;
  using BaseArithmeticsEngine::ToggleMSB;
  CFixedPoint ToggleMSB(const CFixedPoint &a);
  LWECiphertext PXOR(ConstLWECiphertext &a, const LWEPlaintext &b);
  CFixedPoint Not(const CFixedPoint &a);
  LWECiphertext Mux(LWECiphertext s, LWEPlaintext a, LWECiphertext b);
};
