import random

def generate_random_bytes():
    # Initialize variables
    var_10 = 0  # Loop counter (corresponds to rbp - 0x10)
    var_C = 0   # Intermediate value storage (corresponds to rbp - 0x0C)
    var_8 = []  # Buffer to store generated random bytes (corresponds to rbp - 0x08)

    random.seed(0x1337)  # Seed the random number generator

    while var_10 < 0x20:  # Loop until var_10 reaches 32
        # Step 1: Generate a random number
        rand_value = random.randint(0, 0xFFFFFFFF)  # Generate a random 32-bit integer

        # Step 2: Scaling random value
        ecx = rand_value
        edx = 0x6208CECB
        edx *= ecx
        edx >>= 9  # Arithmetic right shift by 9

        # Step 3: Calculate intermediate value
        eax = (ecx >> 31) & 1  # Equivalent to sar eax, 1Fh (extract sign bit)
        edx -= eax  # Perform the subtraction

        # Store in var_C
        var_C = edx

        # Step 4: Further modification
        var_C *= 0x539  # Multiply var_C by 0x539
        ecx -= var_C  # Update ecx

        # Update var_C again
        var_C = ecx

        # Step 5: Prepare to store the result
        rdx = 4  # Equivalent to incrementing ax to get a value of 4
        rax = (rdx + var_C) & 0xFFFFFFFF  # Compute the effective address

        # Calculate effective index for storing the byte (var_10)
        effective_index = var_10

        # Store the byte into var_8
        if len(var_8) <= effective_index:
            var_8.append(0)  # Extend the list if necessary
        var_8[effective_index] = rax & 0xFF  # Store the lowest byte

        # Increment the loop counter
        var_10 += 1

    # Return the final byte array as a hexadecimal string
    return ''.join(format(x, '02x') for x in var_8)  # Return the bytes as a hex string

# Call the function and print the result
result = generate_random_bytes()
print(result)  # This will print the final value of the bytes in the buffer
