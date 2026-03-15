#pragma once

#include <computefhe/BaseArithmeticsEngine.h>
#include <computefhe/ComputeFHE.h>
#include <iostream>
using namespace std;

namespace computefhe {
  class CFHE_Integer {
  private:
    static ComputeFHE *cfhe;
    FixedPoint data;
    size_t size;

  public:
    CFHE_Integer(int d = 0, size_t s = 32, const ArithmeticsEngineType & = AE_OPTIMIZED);
    virtual bool operator==(const CFHE_Integer &);
    virtual bool operator!=(const CFHE_Integer &);
    virtual bool operator>(const CFHE_Integer &);
    virtual bool operator>=(const CFHE_Integer &);
    virtual bool operator<(const CFHE_Integer &);
    virtual bool operator<=(const CFHE_Integer &);
    virtual CFHE_Integer operator+(const CFHE_Integer &);
    virtual CFHE_Integer operator+(uint);
    virtual CFHE_Integer operator-(const CFHE_Integer &);
    virtual CFHE_Integer operator-(uint);
    virtual CFHE_Integer operator*(const CFHE_Integer &);
    virtual CFHE_Integer operator*(uint);
    virtual CFHE_Integer operator=(int n);
    virtual CFHE_Integer operator=(FixedPoint n);
    virtual CFHE_Integer operator-();
    friend ostream& operator<<(ostream &out, const CFHE_Integer& obj);
  };

  ostream& operator<<(ostream &out, const CFHE_Integer& obj);
}

/* TO-DO:
    int -> eint?
    char -> echar?
    short / long -> eshort  / elong?
    custom sized?

    EInt a = 47;
    EInt b = 13;
    cout << a + b << endl
    if ( a < b )
*/
