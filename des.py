import numpy as np
import des_info as des


def des_encrypt(input_block, key):
    # get the left and right half (28 bits) of the round key
    permuted_key = apply_permutation(key, 64, des.pc1)

    key_left = (permuted_key >> 28) & 0xFFFFFFF
    key_right = permuted_key & 0xFFFFFFF

    encrypted = input_block

    for round_num in range(16):
        encrypted, key_left, key_right = des_single_round(
            encrypted, key_left, key_right, round_num)

    encrypted_left = (encrypted >> 32) & 0xFFFF_FFFF
    encrypted_right = encrypted & 0xFFFF_FFFF

    encrypted = (encrypted_right << 32) + encrypted_left

    encrypted = apply_permutation(encrypted, 64, des.inv_initial_permutation)

    return encrypted


def des_single_round(input_block, key_left, key_right, round_num):
    # get the left and right half (32 bits) of the input block
    input_left = (input_block >> 32) & 0xFFFFFFFF
    input_right = input_block & 0xFFFFFFFF

    # get K_i:
    #   shift amount according to shift schedule
    shift_amount = des.left_shift_schedule[round_num]

    #   apply circular shifts to keys left and right halves
    key_left = left_circular_shift(key_left, 28, shift_amount)
    key_right = left_circular_shift(key_right, 28, shift_amount)

    #   combine the shifted halves
    key_shifted = (key_left << 28) + key_right

    #   apply PC2 to the shifted keys to get K_i
    K_i = apply_permutation(key_shifted, 56, des.pc2)

    # get the f function output based on the right input block, and K_i
    f_func_output = des_f_function(input_right, K_i)

    # XOR the left input block with the output of the f function to
    # get the encrypted right half
    right_final = f_func_output ^ input_left

    # the encrypted right half is simply the original right input block
    left_final = input_right

    # combine the left and right output halves to get the round output
    round_out = (left_final << 32) + right_final

    # return the round output, as well as the left and right keys for
    # for the next round
    return round_out, key_left, key_right


def des_f_function(input_block_right: int, K_i: int) -> int:
    expanded_right = apply_permutation(
        input_block_right, 32, des.expansion_permutation)

    sbox_input = expanded_right ^ K_i

    sbox_output = apply_sbox_substitution(sbox_input)

    return apply_permutation(sbox_output, 32, des.permutation_function)


def apply_sbox_substitution(input_from_xor: int) -> int:
    output_number = 0x0

    for i in range(6, 49, 6):
        hextet = (input_from_xor >> (48 - i)) & 0b111111

        col = (hextet & 0b011110) >> 1
        row = ((hextet & 0b100000) >> 4) + (hextet & 0b000001)

        substitution_val = des.sboxes[int(i / 6) - 1][row][col]

        output_number |= substitution_val << (32 - int(i * (2/3)))

    return output_number


def apply_permutation(number: int, input_bit_length: int, permutation) -> int:
    output_bit_length = len(permutation)

    output_number = 0x0
    curr_bit_index = 0

    for bit_index in permutation:
        # the bit at position `bit_index`
        bit = (number >> (input_bit_length - bit_index)) & 0b1

        # shift to the position of `curr_bit_index`
        bit <<= output_bit_length - curr_bit_index - 1

        # put the bit in `output_number`
        output_number |= bit

        curr_bit_index += 1

    return output_number


def left_circular_shift(number: int, num_bits: int, shift_amount: int) -> int:
    mask = (1 << num_bits) - 1

    return ((number << shift_amount) & mask) | (number >> (num_bits - shift_amount))


def right_circular_shift(number: int, num_bits: int, shift_amount: int) -> int:
    mask = (1 << num_bits) - 1

    return (number >> shift_amount) | ((number << (num_bits - shift_amount)) & mask)


print(hex(des_encrypt(0xFFFF_FFFF_FFFF_FFFF, 0xAAAA_AAAA_AAAA_AAAA)))
