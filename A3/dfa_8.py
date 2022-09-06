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

def solve_0_7_10_13(correct, faulty):
    possible_deltas = []
    possible_keybytes = []
    for delta in range(256):
        k0_sols = []
        k7_sols = []
        k10_sols = []
        k13_sols = []

        # eqn 1: 2*delta
        for k0 in range(256):
            rhs = sbox_inv(correct[0] ^ k0) ^ sbox_inv(faulty[0] ^ k0)
            lhs = mult[2,delta]
            if lhs == rhs:
                k0_sols.append(k0)
        # eqn 2: 3*delta
        for k7 in range(256):
            rhs = sbox_inv(correct[7] ^ k7) ^ sbox_inv(faulty[7] ^ k7)
            lhs = mult[3,delta]
            if lhs == rhs:
                k7_sols.append(k7)
        # eqn 3: delta
        for k10 in range(256):
            rhs = sbox_inv(correct[10] ^ k10) ^ sbox_inv(faulty[10] ^ k10)
            lhs = mult[1,delta]
            if lhs == rhs:
                k10_sols.append(k10)
        # eqn 4: delta
        for k13 in range(256):
            rhs = sbox_inv(correct[13] ^ k13) ^ sbox_inv(faulty[13] ^ k13)
            lhs = mult[1,delta]
            if lhs == rhs:
                k13_sols.append(k13)

        if (len(k0_sols) == 0) or (len(k13_sols) == 0) or (len(k10_sols) == 0) or (len(k7_sols) == 0):
            continue
        else:
            possible_deltas.append(delta)
            keybytes = []
            keybytes.append(k0_sols)
            keybytes.append(k7_sols)
            keybytes.append(k10_sols)
            keybytes.append(k13_sols)
            possible_keybytes.append(keybytes)
    return possible_deltas, possible_keybytes

def solve_1_4_11_14(correct, faulty):
    possible_deltas = []
    possible_keybytes = []
    for delta in range(256):
        k1_sols = []
        k4_sols = []
        k11_sols = []
        k14_sols = []

        # eqn 1: 2*delta
        for k1 in range(256):
            rhs = sbox_inv(correct[1] ^ k1) ^ sbox_inv(faulty[1] ^ k1)
            lhs = mult[2,delta]
            if lhs == rhs:
                k1_sols.append(k1)
        # eqn 2: 3*delta
        for k4 in range(256):
            rhs = sbox_inv(correct[4] ^ k4) ^ sbox_inv(faulty[4] ^ k4)
            lhs = mult[3,delta]
            if lhs == rhs:
                k4_sols.append(k4)
        # eqn 3: delta
        for k11 in range(256):
            rhs = sbox_inv(correct[11] ^ k11) ^ sbox_inv(faulty[11] ^ k11)
            lhs = mult[1,delta]
            if lhs == rhs:
                k11_sols.append(k11)
        # eqn 4: delta
        for k14 in range(256):
            rhs = sbox_inv(correct[14] ^ k14) ^ sbox_inv(faulty[14] ^ k14)
            lhs = mult[1,delta]
            if lhs == rhs:
                k14_sols.append(k14)

        if (len(k1_sols) == 0) or (len(k4_sols) == 0) or (len(k11_sols) == 0) or (len(k14_sols) == 0):
            continue
        else:
            possible_deltas.append(delta)
            keybytes = []
            keybytes.append(k1_sols)
            keybytes.append(k4_sols)
            keybytes.append(k11_sols)
            keybytes.append(k14_sols)
            possible_keybytes.append(keybytes)
    return possible_deltas, possible_keybytes

def solve_2_5_8_15(correct, faulty):
    possible_deltas = []
    possible_keybytes = []
    for delta in range(256):
        k2_sols = []
        k5_sols = []
        k8_sols = []
        k15_sols = []

        # eqn 1: 2*delta
        for k2 in range(256):
            rhs = sbox_inv(correct[2] ^ k2) ^ sbox_inv(faulty[2] ^ k2)
            lhs = mult[2,delta]
            if lhs == rhs:
                k2_sols.append(k2)
        # eqn 2: 3*delta
        for k5 in range(256):
            rhs = sbox_inv(correct[5] ^ k5) ^ sbox_inv(faulty[5] ^ k5)
            lhs = mult[3,delta]
            if lhs == rhs:
                k5_sols.append(k5)
        # eqn 2: delta
        for k8 in range(256):
            rhs = sbox_inv(correct[8] ^ k8) ^ sbox_inv(faulty[8] ^ k8)
            lhs = mult[1,delta]
            if lhs == rhs:
                k8_sols.append(k8)
        # eqn 3: delta
        for k15 in range(256):
            rhs = sbox_inv(correct[15] ^ k15) ^ sbox_inv(faulty[15] ^ k15)
            lhs = mult[1,delta]
            if lhs == rhs:
                k15_sols.append(k15)

        if (len(k2_sols) == 0) or (len(k5_sols) == 0) or (len(k8_sols) == 0) or (len(k15_sols) == 0):
            continue
        else:
            possible_deltas.append(delta)
            keybytes = []
            keybytes.append(k2_sols)
            keybytes.append(k5_sols)
            keybytes.append(k8_sols)
            keybytes.append(k15_sols)
            possible_keybytes.append(keybytes)
    return possible_deltas, possible_keybytes

def solve_3_6_9_12(correct, faulty):
    possible_deltas = []
    possible_keybytes = []
    for delta in range(256):
        k3_sols = []
        k6_sols = []
        k9_sols = []
        k12_sols = []

        # eqn 1: 2*delta
        for k3 in range(256):
            rhs = sbox_inv(correct[3] ^ k3) ^ sbox_inv(faulty[3] ^ k3)
            lhs = mult[2,delta]
            if lhs == rhs:
                k3_sols.append(k3)
        # eqn 2: 3*delta
        for k6 in range(256):
            rhs = sbox_inv(correct[6] ^ k6) ^ sbox_inv(faulty[6] ^ k6)
            lhs = mult[3,delta]
            if lhs == rhs:
                k6_sols.append(k6)
        # eqn 3: delta
        for k9 in range(256):
            rhs = sbox_inv(correct[9] ^ k9) ^ sbox_inv(faulty[9] ^ k9)
            lhs = mult[1,delta]
            if lhs == rhs:
                k9_sols.append(k9)
        # eqn 4: delta
        for k12 in range(256):
            rhs = sbox_inv(correct[12] ^ k12) ^ sbox_inv(faulty[12] ^ k12)
            lhs = mult[1,delta]
            if lhs == rhs:
                k12_sols.append(k12)

        if (len(k3_sols) == 0) or (len(k6_sols) == 0) or (len(k9_sols) == 0) or (len(k12_sols) == 0):
            continue
        else:
            possible_deltas.append(delta)
            keybytes = []
            keybytes.append(k3_sols)
            keybytes.append(k6_sols)
            keybytes.append(k9_sols)
            keybytes.append(k12_sols)
            possible_keybytes.append(keybytes)
    return possible_deltas, possible_keybytes

deltas, keys = solve_0_7_10_13(ct[0], ct_[0])
k0s = [x[0] for x in keys]
k7s = [x[1] for x in keys]
k10s = [x[2] for x in keys]
k13s = [x[3] for x in keys]

df = pd.DataFrame({'Delta': deltas,
                   'K0': k0s,
                   'K7': k7s,
                   'K10': k10s,
                   'K13': k13s
                   })
print(df.to_markdown(index=False, tablefmt='simple'))

deltas, keys = solve_0_7_10_13(ct[1], ct_[1])
k0s = [x[0] for x in keys]
k7s = [x[1] for x in keys]
k10s = [x[2] for x in keys]
k13s = [x[3] for x in keys]

df = pd.DataFrame({'Delta': deltas,
                   'K0': k0s,
                   'K7': k7s,
                   'K10': k10s,
                   'K13': k13s
                   })
print(df.to_markdown(index=False, tablefmt='simple'))

# deltas, keys = solve_1_4_11_14(ct[0], ct_[0])
# k1s = [x[0] for x in keys]
# k4s = [x[1] for x in keys]
# k11s = [x[2] for x in keys]
# k14s = [x[3] for x in keys]

# df = pd.DataFrame({'Delta': deltas,
#                    'K1': k1s,
#                    'K4': k4s,
#                    'K11': k11s,
#                    'K14': k14s
#                    })
# print(df.to_markdown(index=False, tablefmt='simple'))

# deltas, keys = solve_2_5_8_15(ct[0], ct_[0])
# k2s = [x[0] for x in keys]
# k5s = [x[1] for x in keys]
# k8s = [x[2] for x in keys]
# k15s = [x[3] for x in keys]

# df = pd.DataFrame({'Delta': deltas,
#                    'K2': k2s,
#                    'K5': k5s,
#                    'K8': k8s,
#                    'K15': k15s
#                    })
# print(df.to_markdown(index=False, tablefmt='simple'))

# deltas, keys = solve_3_6_9_12(ct[0], ct_[0])
# k3s = [x[0] for x in keys]
# k6s = [x[1] for x in keys]
# k9s = [x[2] for x in keys]
# k12s = [x[3] for x in keys]

# df = pd.DataFrame({'Delta': deltas,
#                    'K3': k3s,
#                    'K6': k6s,
#                    'K9': k9s,
#                    'K12': k12s
#                    })
# print(df.to_markdown(index=False, tablefmt='simple'))
