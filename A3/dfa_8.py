import numpy as np

ct = np.load("ciphertexts.npy")
ct_ = np.load("faultytexts.npy")

s = np.load("sbox.npy")
s_ = np.load("sbox_inv.npy")

def sbox(byte):
    return s[byte]

def sbox_inv(byte):
    return s_[byte]
