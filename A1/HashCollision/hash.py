import time
import timeit

flag = "ctf{its_dummy_flag}"
prime = 19

#for substitution of characters
def substitution(char):
    switch = {
        'a' : 'z',
        'b' : 'j',
        'c' : 's',
        'd' : 'q',
        'e' : 'r',
        'f' : 'y',
        'g' : 'i',
        'h' : 'w',
        'i' : 'm',
        'j' : 'h',
        'k' : 'f',
        'l' : 'g',
        'm' : 'b',
        'n' : 'c',
        'o' : 'x',
        'p' : 'e',
        'q' : 'a',
        'r' : 't',
        's' : 'u',
        't' : 'o',
        'u' : 'd',
        'v' : 'k',
        'w' : 'n',
        'x' : 'l',
        'y' : 'p',
        'z' : 'v',
        '{' : '=',
        '}' : '_',
        '=' : '}',
        '_' : '{'
        }
    return switch.get(char,char)

# compute hash of the supplied string
def compute_hash(password):
    password = password.ljust(prime,"=")[0:prime]
    print(password)
    hash = ""
    for i in range(prime):
        hash += substitution(password[(7*i+4)%prime])
        print(hash)
    return hash

# to check the correctness of the supplied password
def password_checker(password):
    hash = compute_hash(password)
    for i in range(len(flag)):
        time.sleep(1)
        if(flag_hash[i]!=hash[i]):
            return False
    return True

def password_handler(password):
    if(password):
        # measure the time measured to check password correctness
        start = timeit.default_timer()
        if(password_checker(password)):
            print("Access Granted")
        else:
            print("Invalid password")
        end = timeit.default_timer()
        runtime = end-start
        print("Time taken to verify = ", runtime)

flag_hash = compute_hash(flag) # mb_u{oqg=biops{yydz
print("Enter the password:")
# take user input password
password = input()
password_handler(password)
