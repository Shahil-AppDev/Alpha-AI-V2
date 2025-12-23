import os
import subprocess

def vulnerable_function(user_input):
    # SQL Injection vulnerability
    query = "SELECT * FROM users WHERE id = %s" % user_input
    cursor.execute(query)
    
    # Command injection vulnerability
    os.system("ls " + user_input)
    
    # Hardcoded password
    password = "supersecret123"
    
    # Weak cryptography
    import hashlib
    hash_value = hashlib.md5(user_input.encode()).hexdigest()
    
    # Insecure deserialization
    import pickle
    data = pickle.loads(user_input)
    
    return password
