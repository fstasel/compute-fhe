/*
 *  SPDX-FileCopyrightText: 2026 Faris Serdar Taşel <fst@cankaya.edu.tr>
 *  SPDX-FileCopyrightText: 2026 Efe Çiftci <efeciftci@cankaya.edu.tr>
 *
 *  SPDX-License-Identifier: MIT
 */

/**
 * @file ALUStandard.h
 * @brief Defines the standard ALU implementation using fundamental FHE logic
 * gates.
 */

#pragma once
#include <computefhe/BaseALU.h>

namespace computefhe {

    /**
     * @class ALUStandard
     * @brief Standard ALU implementation using fundamental FHE logic gates.
     *
     * Provides the baseline implementation for homomorphic arithmetic and logic
     * operations using standard two-input gates.
     */
    class ALUStandard : virtual public BaseALU {
      public:
        ALUStandard(ComputeFHE *cfhe);

        // Logic Gates
        virtual BinaryDigit Gate_MAJ(const BinaryDigit &a, const BinaryDigit &b,
                                     const BinaryDigit &c);
        virtual BinaryDigit Gate_XOR3(const BinaryDigit &a,
                                      const BinaryDigit &b,
                                      const BinaryDigit &c);
        virtual BinaryDigit Gate_MulAdd(const BinaryDigit &m,
                                        const BinaryDigit &a,
                                        const BinaryDigit &b,
                                        BinaryDigit *carry_out = nullptr);
        virtual BinaryDigit Gate_DigitSum(const BinaryDigit &e1,
                                          const BinaryDigit &e0,
                                          const BinaryDigit &s0);

        // Interface
        virtual FixedPoint Mux(const BinaryDigit &s, const FixedPoint &a,
                               const FixedPoint &b);
        virtual FixedPoint ToggleMSB(const FixedPoint &a);

        virtual FixedPoint ShiftLeft(const FixedPoint &a, size_t shift);
        virtual FixedPoint ShiftRight(const FixedPoint &a, size_t shift,
                                      bool is_arithmetic = false);

        virtual void Swap_if(const BinaryDigit &cond, BinaryDigit &a,
                             BinaryDigit &b);
        virtual void Swap_if(const BinaryDigit &cond, FixedPoint &a,
                             FixedPoint &b);

        virtual void HalfAdder(const BinaryDigit &a, const BinaryDigit &b,
                               BinaryDigit &sum, BinaryDigit &carry_out);
        virtual void HalfSubtractor(const BinaryDigit &a, const BinaryDigit &b,
                                    BinaryDigit &sum, BinaryDigit &carry_out);
        virtual void FullAdder(const BinaryDigit &a, const BinaryDigit &b,
                               const BinaryDigit &c, BinaryDigit &sum,
                               BinaryDigit &carry_out);

        virtual FixedPoint Add(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint AddCNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Sub(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint SubC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint SubNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint SubCNC(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Neg(const FixedPoint &a);
        virtual FixedPoint Not(const FixedPoint &a);
        virtual BinaryDigit CmpNotEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLTEq_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGT_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGTEq_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLT_U(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLTEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGT(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpGTEq(const FixedPoint &a, const FixedPoint &b);
        virtual BinaryDigit CmpLT(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint FullMul(const FixedPoint &a, const FixedPoint &b);
        virtual FixedPoint Mul(const FixedPoint &a, const FixedPoint &b);
        virtual void DivU(const FixedPoint &a, const FixedPoint &b,
                          FixedPoint &q, FixedPoint &r);

        virtual FixedPoint PAdd(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PAddCNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PSub(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubNC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint PSubCNC(const FixedPoint &pa, const FixedPoint &b);
        virtual FixedPoint CPSub(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint CPSubC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint CPSubNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint CPSubCNC(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PFullMul(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PFullMulFast(const FixedPoint &a,
                                        const FixedPoint &pb);
        virtual FixedPoint PBoothsMul(const FixedPoint &a,
                                      const FixedPoint &pb);
        virtual FixedPoint PMul(const FixedPoint &a, const FixedPoint &pb);
        virtual FixedPoint PMulFast(const FixedPoint &a, const FixedPoint &pb);

        virtual uint Get_CtCtAdd_Cost(size_t n_bits);
        virtual uint Get_CtCtAddNC_Cost(size_t n_bits);
        virtual uint Get_CtCtSubC_Cost(size_t n_bits);
        virtual uint Get_CtCtSubNC_Cost(size_t n_bits);
        virtual uint Get_CtPtAddC_Cost(size_t n_bits);
        virtual uint Get_PtCtSub_Cost(size_t n_bits);
        virtual uint Get_CtPtSubCNC_Cost(size_t n_bits);
        virtual uint Get_CtNeg_Cost(size_t n_bits);
        virtual uint Get_PtFullMul_Cost(const FixedPoint &pt, size_t ct_n_bits,
                                        size_t &out_n_bits);
        virtual uint Get_Pt2sCompFullMul_Cost(const FixedPoint &pt,
                                              size_t ct_n_bits);
        virtual uint Get_PtMul_Cost(const FixedPoint &pt);
        virtual uint Get_Pt2sCompMul_Cost(const FixedPoint &pt);
        virtual uint Get_BoothsMul_Cost(const FixedPoint &pt, size_t ct_n_bits);
    };
} // namespace computefhe
