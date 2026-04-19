# test1.py (INTENTIONALLY VULNERABLE FOR TESTING)

import os
import subprocess
import pickle
import random

# ❌ Hardcoded password
password = "12345"

def login(user_input):
    if user_input == password:
        print("Access granted")
    else:
        print("Access denied")

# ❌ Dangerous eval (code injection)
user_input = input("Enter something: ")
eval(user_input)

# ❌ Command injection
os.system("echo " + user_input)

# ❌ Unsafe subprocess usage
subprocess.Popen("ls " + user_input, shell=True)

# ❌ Unsafe deserialization
data = pickle.loads(b"cos\nsystem\n(S'echo hacked'\ntR.")

# ❌ Weak random (not secure)
print(random.random())

# ❌ Debug mode enabled (example pattern)
debug = True