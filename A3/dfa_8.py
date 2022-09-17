import numpy as np
from multiprocessing import Pool
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

def reverseKey(key10):
    subKeys = np.zeros(176, dtype= np.uint8)
    for i in range(160, 176):
        subKeys[i] = key10[i - 160]
    for i in range(156, -1, -4):
        if i % 16 == 0:
            subKeys[i] = subKeys[i + 16] ^ sbox(subKeys[i+13]) ^ rcon[i >> 4]
            subKeys[i+1] = subKeys[i+17] ^ sbox(subKeys[i+14])
            subKeys[i+2] = subKeys[i+18] ^ sbox(subKeys[i+15])
            subKeys[i+3] = subKeys[i+19] ^ sbox(subKeys[i+12])
        else:
            subKeys[i] = subKeys[i + 16] ^ sbox(subKeys[i+12])
            subKeys[i+1] = subKeys[i+17] ^ sbox(subKeys[i+13])
            subKeys[i+2] = subKeys[i+18] ^ sbox(subKeys[i+14])
            subKeys[i+3] = subKeys[i+19] ^ sbox(subKeys[i+15])
    return subKeys
    
def get_fault_column(position):
    if position == 0 or position == 5 or position == 10 or position == 15:
        return 0
    elif position == 4 or position == 9 or position == 14 or position == 3:
        return 1
    elif position == 8 or position == 13 or position == 2 or position == 7:
        return 2
    elif position == 12 or position == 1 or position == 6 or position == 11:
        return 3
    else:
        return None

def get_factors(column):
    if column == 0:
        return [[2, 1, 1, 3],
                [1, 1, 3, 2],
                [1, 3, 2, 1],
                [3, 2, 1, 1]]
    elif column == 1:
        return [[3, 2, 1, 1],
                [2, 1, 1, 3],
                [1, 1, 3, 2],
                [1, 3, 2, 1]]
    elif column == 2:
        return [[1, 3, 2, 1],
                [3, 2, 1, 1],
                [2, 1, 1, 3],
                [1, 1, 3, 2]]
    elif column == 3:
        return [[1, 1, 3, 2],
                [1, 3, 2, 1],
                [3, 2, 1, 1],
                [2, 1, 1, 3]]
    else:
        return None

# Solve 1 set of equations (4 key bytes)
def solve(correct, faulty, byte_positions, factors):
    possibilities = []
    for delta in range(256):
        b_sols = []

        for i in range(4):
            bi_sols = []
            lhs = mult[factors[i],delta]
            for kb in range(256):
                rhs = sbox_inv(correct[byte_positions[i]] ^ kb) ^ sbox_inv(faulty[byte_positions[i]] ^ kb)
                if lhs == rhs:
                    bi_sols.append(kb)
            b_sols.append(bi_sols)

        if (len(b_sols[0]) == 0) or (len(b_sols[1]) == 0) or (len(b_sols[2]) == 0) or (len(b_sols[3]) == 0):
            continue
        else:
            for b0 in b_sols[0]:
                for b1 in b_sols[1]:
                    for b2 in b_sols[2]:
                        for b3 in b_sols[3]:
                            keybytes = (b0, b1, b2, b3)
                            possibilities.append(keybytes)
    return possibilities

if __name__ == '__main__':
    
    keys_p0 = []
    keys_p1 = []
    keys_p2 = []
    keys_p3 = []
    for pair_num in range(4):
        keys_0_7_10_13 = []
        keys_1_4_11_14 = []
        keys_2_5_8_15 = []
        keys_3_6_9_12 = []
        for position in range(16):
            col_num = get_fault_column(position)
            assert(col_num!=None)
            factors = get_factors(col_num)
            assert(factors!=None)
            keys_0_7_10_13.extend(solve(ct[pair_num], ct_[pair_num], [0, 13, 10, 7], factors[0]))
            keys_1_4_11_14.extend(solve(ct[pair_num], ct_[pair_num], [4, 1, 14, 11], factors[1]))
            keys_2_5_8_15.extend(solve(ct[pair_num], ct_[pair_num], [8, 5, 2, 15], factors[2]))
            keys_3_6_9_12.extend(solve(ct[pair_num], ct_[pair_num], [12, 9, 6, 3], factors[3]))
        keys_p0.append(keys_0_7_10_13)
        keys_p1.append(keys_1_4_11_14)
        keys_p2.append(keys_2_5_8_15)
        keys_p3.append(keys_3_6_9_12)
    final_set_0 = list(set(keys_p0[0]) & set(keys_p0[1]) & set(keys_p0[2]) & set(keys_p0[3]))
    final_set_1 = list(set(keys_p1[0]) & set(keys_p1[1]) & set(keys_p1[2]) & set(keys_p1[3]))
    final_set_2 = list(set(keys_p2[0]) & set(keys_p2[1]) & set(keys_p2[2]) & set(keys_p2[3]))
    final_set_3 = list(set(keys_p3[0]) & set(keys_p3[1]) & set(keys_p3[2]) & set(keys_p3[3]))
    print(len(final_set_0), final_set_0)
    print(len(final_set_1), final_set_1)
    print(len(final_set_2), final_set_2)
    print(len(final_set_3), final_set_3)

    key10 = [0] * 16
    indexGroups = [[0, 7, 10, 13], [1, 4, 11, 14], [2, 5, 8, 15], [3, 6, 9, 12]]
    for i in range(0, 4):
        key10[indexGroups[0][i]] = final_set_0[0][i]
        key10[indexGroups[1][i]] = final_set_1[0][i]
        key10[indexGroups[2][i]] = final_set_2[0][i]
        key10[indexGroups[3][i]] = final_set_3[0][i]

    np.save("key10", key10)
    #key10 = np.load("key10.npy", "r").astype(np.uint8)
    allKeys = reverseKey(key10)
    allKey_dict = {}
    print("Secret Key: ", allKeys[0:16])
    for i in range(1, 11, 1):
        print("Round {}:".format(i), allKeys[16*i : 16*(i+1)])
    np.save("allKeys", allKeys)
