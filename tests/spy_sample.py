# SPy コンパイラを検証するためのサンプル(Python としても Scratch としても動く)
from cloudiamond_scratch.scratch.spyrt import *

A = Lst(8)
OUT = Lst(16)
T = Vars(5)
CH = Lst(["a", "b", "c", " ", "1"])
CNT = Lst(0)
K = 7
done = Var(0)
total = Var(0)


def add3(x, y, z):
    return x + y + z


def fact(n):
    r = 1
    for i in range(1, n + 1):
        r = r * i
    return r


def pick(a, b):
    if a > b:
        return a
    else:
        return b


def inner():
    global total
    for i in unroll(5):
        T[i] = i * i + K
    for i in unroll(4):
        for j in unroll(4):
            if i < j:
                total = total + i * 10 + j
            else:
                total = total - 1
    for i in range(8):
        A[i] = (i * 37 + 11) % 16
    s = 0
    k = 0
    while k < 8:
        s += A[k]
        k += 1
    OUT[0] = s
    OUT[1] = add3(1, 2, 3) * 2 + add3(A[1], A[2], 0)
    OUT[2] = fact(6)
    OUT[3] = (A[1] * 100003 + 1234567) // 256 % 256
    OUT[4] = (A[0] - 20) % 4
    OUT[5] = list_index_of(CH, "B")
    OUT[6] = T[0] + T[4]
    j = 0
    if A[0] != 11 and (A[1] >= 3 or A[2] <= 0):
        j = 5
    elif A[3] > 1:
        j = 6
    else:
        j = 7
    OUT[7] = j
    OUT[8] = length_of(join(12, join("ab", 345)))
    OUT[9] = letter_of(2, join("xyz", 7))
    q = 0
    for i in range(254, 249, -1):
        q = q + i
    OUT[10] = q
    OUT[11] = len(A) + len(OUT)
    OUT[12] = pick(add3(1, 1, 1), fact(2)) * 100 + pick(1, 2)
    OUT[13] = list_index_of(CH, 1)
    CNT.clear()
    for i in range(5):
        CNT.append(i * i)
    del CNT[1]
    OUT[14] = len(CNT) * 1000 + CNT[1]
    big = A[7] * 123456789 * 1000 + 98765
    OUT[15] = big // 7 % 1000


@when_flag
def main():
    global done
    inner()
    done = 1
