import numpy as np
import pandas as pd

ct = np.load("ciphertexts.npy")
ct_ = np.load("faultytexts.npy")

s = np.load("sbox.npy")
s_ = np.load("sbox_inv.npy")

mult = np.load("multiplies.npy")
rcon = np.load("rcon.npy")

def sbox(byte):
    return s[byte]

def sbox_inv(byte):
    return s_[byte]

def solve(correct, faulty, bytes, factors):
    assert(len(bytes) == 4)
    assert(len(factors) == 4)
    assert(len(correct) == 16)
    assert(len(faulty) == 16)

    possibilities = []
    for delta in range(256):
        b0_sols = []
        b1_sols = []
        b2_sols = []
        b3_sols = []

        # eqn 1
        lhs = mult[factors[0],delta]
        for b0 in range(256):
            rhs = sbox_inv(correct[bytes[0]] ^ b0) ^ sbox_inv(faulty[bytes[0]] ^ b0)
            if lhs == rhs:
                b0_sols.append(b0)
        # eqn 2
        lhs = mult[factors[1],delta]
        for b1 in range(256):
            rhs = sbox_inv(correct[bytes[1]] ^ b1) ^ sbox_inv(faulty[bytes[1]] ^ b1)
            if lhs == rhs:
                b1_sols.append(b1)
        # eqn 3
        lhs = mult[factors[2],delta]
        for b2 in range(256):
            rhs = sbox_inv(correct[bytes[2]] ^ b2) ^ sbox_inv(faulty[bytes[2]] ^ b2)
            if lhs == rhs:
                b2_sols.append(b2)
        # eqn 4
        lhs = mult[factors[3],delta]
        for b3 in range(256):
            rhs = sbox_inv(correct[bytes[3]] ^ b3) ^ sbox_inv(faulty[bytes[3]] ^ b3)
            if lhs == rhs:
                b3_sols.append(b3)

        if (len(b0_sols) == 0) or (len(b1_sols) == 0) or (len(b2_sols) == 0) or (len(b3_sols) == 0):
            continue
        else:
            for b0 in b0_sols:
                for b1 in b1_sols:
                    for b2 in b2_sols:
                        for b3 in b3_sols:
                            keybytes = (b0, b1, b2, b3)
                            possibilities.append(keybytes)
    return possibilities

keys_0_7_10_13 = solve(ct[0], ct_[0], [0, 7, 10, 13], [2, 3, 1, 1])
keys_1_4_11_14 = solve(ct[0], ct_[0], [1, 4, 11, 14], [2, 3, 1, 1])
keys_2_5_8_15 = solve(ct[0], ct_[0], [2, 5, 8, 15], [2, 3, 1, 1])
keys_3_6_9_12 = solve(ct[0], ct_[0], [3, 6, 9, 12], [2, 3, 1, 1])

# keys = []
# for p0 in keys_0_7_10_13:
#     for p1 in keys_1_4_11_14:
#         for p2 in keys_2_5_8_15:
#             for p3 in keys_3_6_9_12:
#                 key = (p0[0], p1[0], p2[0], p3[0],
#                        p1[1], p2[1], p3[1], p0[1],
#                        p2[2], p3[2], p0[2], p1[2],
#                        p3[3], p0[3], p1[3], p2[3]
#                       )
#                 keys.append(key)
