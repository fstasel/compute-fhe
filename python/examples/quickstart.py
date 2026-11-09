"""Run with --simulation for a fast native simulator demonstration."""
import argparse
from computefhe import Context, Eint8, Euint8, EncryptedVector, select

parser = argparse.ArgumentParser(description=__doc__)
parser.add_argument("--simulation", action="store_true")
args = parser.parse_args()

with Context(simulation=args.simulation):
    a, b = Eint8(42), Eint8(15)
    print("sum:", (a + b).decrypt())
    print("maximum:", select(a > b, a, b).decrypt())
    values = EncryptedVector([Eint8(10), Eint8(20), Eint8(30)])
    index = Euint8(1)
    values[index] = values[index] + 5
    print("selected value:", values[index].decrypt())
