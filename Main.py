from Keccak import Keccak

TYPE_RAW_STRING = "RAW"
TYPE_FILE = "FILE"

print()
print("Welcome to Secure Hash Algorithm standard 3 (SHA-3) :)")

input_type = input("To hash a raw input message type '" + str(TYPE_RAW_STRING)
                   + "' and to hash a file type '" + str(TYPE_FILE) + "'.\n")

print()
variant = int(input("Enter the SHA3 variant to use: \n"
                    + str(Keccak.VARIANT_SHA3_224) + ".\t" + "SHA3 224" + "\n"
                    + str(Keccak.VARIANT_SHA3_256) + ".\t" + "SHA3 256" + "\n"
                    + str(Keccak.VARIANT_SHA3_384) + ".\t" + "SHA3 384" + "\n"
                    + str(Keccak.VARIANT_SHA3_512) + ".\t" + "SHA3 512" + "\n"))

keccak = None
try:
    keccak = Keccak(variant)
except ValueError as v:
    print(v)
    exit(0)

original_hash = current_hash = None

if input_type == TYPE_RAW_STRING:
    message = input("Enter a message: ")
    original_hash = keccak.get_hash_of(message.encode())
    print("Original Hash:" + "\t" + str(original_hash)[2:-1])
    print()

    message = input("Re-enter the message: ")
    keccak = Keccak(variant)
    current_hash = keccak.get_hash_of(message.encode())
    print("Current Hash: " + "\t" + str(current_hash)[2:-1])
    print()

elif input_type == TYPE_FILE:
    file_name = input("Enter a file name: ")
    file = open(file_name, "rb")
    contents = file.read()
    original_hash = keccak.get_hash_of(contents)
    print("Original Hash:" + "\t" + str(original_hash)[2:-1])
    print()
    file.close()

    file_name = input("Re-enter the file name: ")
    file = open(file_name, "rb")
    contents = file.read()
    keccak = Keccak(variant)
    current_hash = keccak.get_hash_of(contents)
    print("Current Hash: " + "\t" + str(current_hash)[2:-1])
    print()
    file.close()

print()
if current_hash == original_hash:
    print("Verification successful!")

else:
    print("Verification failed!")
