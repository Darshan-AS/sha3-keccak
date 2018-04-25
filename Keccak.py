import binascii


class Keccak:
    VARIANT_SHA3_224 = 1
    VARIANT_SHA3_256 = 2
    VARIANT_SHA3_384 = 3
    VARIANT_SHA3_512 = 4

    __STATE_LENGTH = 1600
    __DELIMITED_SUFFIX = 0x06

    __SHA3_224_RATE_LENGTH = 1152
    __SHA3_224_HASH_LENGTH = 224

    __SHA3_256_RATE_LENGTH = 1088
    __SHA3_256_HASH_LENGTH = 256

    __SHA3_384_RATE_LENGTH = 832
    __SHA3_384_HASH_LENGTH = 384

    __SHA3_512_RATE_LENGTH = 576
    __SHA3_512_HASH_LENGTH = 512

    def __init__(self, variant=VARIANT_SHA3_256):
        self.__state_bytes_length = self.__STATE_LENGTH // 8
        self.__delimited_suffix = self.__DELIMITED_SUFFIX

        if variant == self.VARIANT_SHA3_224:
            self.__rate_bytes_length = self.__SHA3_224_RATE_LENGTH // 8
            self.__hash_bytes_length = self.__SHA3_224_HASH_LENGTH // 8

        elif variant == self.VARIANT_SHA3_256:
            self.__rate_bytes_length = self.__SHA3_256_RATE_LENGTH // 8
            self.__hash_bytes_length = self.__SHA3_256_HASH_LENGTH // 8

        elif variant == self.VARIANT_SHA3_384:
            self.__rate_bytes_length = self.__SHA3_384_RATE_LENGTH // 8
            self.__hash_bytes_length = self.__SHA3_384_HASH_LENGTH // 8

        elif variant == self.VARIANT_SHA3_512:
            self.__rate_bytes_length = self.__SHA3_512_RATE_LENGTH // 8
            self.__hash_bytes_length = self.__SHA3_512_HASH_LENGTH // 8

        else:
            raise ValueError("Invalid Variant of Keccak!")

        self.__state_in_bytes = bytearray([0 for i in range(self.__state_bytes_length)])
        self.__capacity_bytes_length = self.__state_bytes_length - self.__rate_bytes_length
        self.__hash_bytes = bytearray()

    @staticmethod
    def __rotate_word(word, n):
        return ((word >> (64 - (n % 64))) + (word << (n % 64))) % (1 << 64)

    @staticmethod
    def __load_64_bytes(byte_array):
        return sum((byte_array[i] << (8 * i)) for i in range(8))

    @staticmethod
    def __store_64_bytes(integer):
        return list((integer >> (8 * i)) % 256 for i in range(8))

    def __run_inner_hash_functions(self, lanes):
        R = 1
        for round in range(24):

            # θ
            C = [lanes[x][0] ^ lanes[x][1] ^ lanes[x][2] ^ lanes[x][3] ^ lanes[x][4] for x in range(5)]
            D = [C[(x + 4) % 5] ^ self.__rotate_word(C[(x + 1) % 5], 1) for x in range(5)]
            lanes = [[lanes[x][y] ^ D[x] for y in range(5)] for x in range(5)]

            # ρ and π
            (x, y) = (1, 0)
            current = lanes[x][y]
            for t in range(24):
                (x, y) = (y, (2 * x + 3 * y) % 5)
                (current, lanes[x][y]) = (lanes[x][y], self.__rotate_word(current, (t + 1) * (t + 2) // 2))

            # χ
            for y in range(5):
                T = [lanes[x][y] for x in range(5)]
                for x in range(5):
                    lanes[x][y] = T[x] ^ ((~T[(x + 1) % 5]) & T[(x + 2) % 5])

            # ι
            for j in range(7):
                R = ((R << 1) ^ ((R >> 7) * 0x71)) % 256
                if R & 2:
                    lanes[0][0] = lanes[0][0] ^ (1 << ((1 << j) - 1))

        return lanes

    def __run_hash_function(self):
        # In column first order
        lanes = [[self.__load_64_bytes(self.__state_in_bytes[8 * (x + 5 * y):
                                                             8 * (x + 5 * y) + 8])
                  for y in range(5)]
                 for x in range(5)]

        lanes = self.__run_inner_hash_functions(lanes)

        state_in_bytes = bytearray(200)
        for x in range(5):
            for y in range(5):
                state_in_bytes[8 * (x + 5 * y):
                               8 * (x + 5 * y) + 8] = self.__store_64_bytes(lanes[x][y])

        self.__state_in_bytes = state_in_bytes

    def get_hash_of(self, input_bytes):
        block_size = 0
        message_offset = 0

        # === Absorb all the input blocks ===
        while message_offset < len(input_bytes):
            block_size = min(len(input_bytes) - message_offset, self.__rate_bytes_length)

            for i in range(block_size):
                self.__state_in_bytes[i] ^= input_bytes[message_offset + i]

            message_offset += block_size

            if block_size == self.__rate_bytes_length:
                self.__run_hash_function()
                block_size = 0

        # === Do the padding and switch to the squeezing phase ===
        self.__state_in_bytes[block_size] ^= self.__delimited_suffix

        if ((self.__delimited_suffix & 0x80) != 0) and (block_size == (self.__rate_bytes_length - 1)):
            self.__run_hash_function()

        self.__state_in_bytes[self.__rate_bytes_length - 1] ^= 0x80
        self.__run_hash_function()

        # === Squeeze out all the output blocks ===
        while self.__hash_bytes_length > 0:
            block_size = min(self.__hash_bytes_length, self.__rate_bytes_length)
            self.__hash_bytes += self.__state_in_bytes[0: block_size]
            self.__hash_bytes_length -= block_size

            if self.__hash_bytes_length > 0:
                self.__run_hash_function()

        return binascii.hexlify(self.__hash_bytes)
