# The large number
large_number = 0x73EDA753299D7D483339D80809A1D80553BDA402FFFE5BFEFFFFFFFF00000000

# Convert the large number to a hexadecimal string
hex_str = hex(large_number)[2:]  # Remove the '0x' prefix

# Pad the hexadecimal string with leading zeros to make its length a multiple of 16
hex_str = hex_str.zfill(64)

# Split the hexadecimal string into four 16-character chunks
chunks = [hex_str[i : i + 16] for i in range(0, len(hex_str), 16)]

# Convert each chunk from hexadecimal to a decimal number
u64_array = [int(chunk, 16) for chunk in chunks]

# Print the result
# print(u64_array)
for chunk in chunks:
    print(f"0x{chunk}")
