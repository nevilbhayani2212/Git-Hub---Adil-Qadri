import random

def generate_otp():
    return ''.join(random.choice('0123456789') for _ in range(6))