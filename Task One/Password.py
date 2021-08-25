import ast
import sys
import os
from typing import Dict, List

MINIMUM_LENGTH = 7
MAXIMUM_LENGTH = 25
SUCCESSION_LENGTH = 3

COMMON_PASSWORDS_FILE = os.path.join(sys.path[0], "common-passwords.txt")


def _check_password(password: str) -> int:
    lowercase_seen = False
    uppercase_seen = False
    digit_seen = False
    characters_seen = 0
    successive_characters_seen = 0
    current_succession_length = 0
    previous_character = ""
    common_passwords_seen = 0

    # Reformat passwords file from raw list to one stored as a dictonary organised
    # by lastt characctter then password length.
    # common_passwords = {}
    # with open(COMMON_PASSWORDS_FILE) as file:
    #     lines = file.readlines()
    #     for line in lines:
    #         line = line.rstrip()
    #         last_character = line[-1]
    #         line_length = len(line)
            
    #         if last_character not in common_passwords:
    #             common_passwords[last_character] = {}
    #         if line_length not in common_passwords[last_character]:
    #             common_passwords[last_character][line_length] = []
    #         common_passwords[last_character][line_length].append(line)
    # from pprint import pprint
    # pprint(common_passwords)

    with open(COMMON_PASSWORDS_FILE) as file:
        contents = file.read()
        # common_passwords: Dict[last character in password, Dict[password length, common passwords of this length with defined last characcter]]
        common_passwords: Dict[int, Dict[str, List[str]]] = ast.literal_eval(contents)
    # Find the length of the longest stored common password.
    common_password_maximum_length = 0
    for common_passwords_for_character in common_passwords.values():
        longest_length_for_character = max(common_passwords_for_character.keys())
        if longest_length_for_character > common_password_maximum_length:
            common_password_maximum_length = longest_length_for_character

    previous_seen_text = ""
 
    # Loop through the password to determine the properties
    # i.e. the length, components missing, number of common
    # passwords seen, number of successive character sequences seen.
    for character in password:
        # Count this as we go rather than doing len(password) to allow
        # this to be easily changed to taking in a character iterator.
        characters_seen += 1

        # Only look at characters before the maximum length as all ones
        # after tthis will be deleted.
        if characters_seen <= MAXIMUM_LENGTH:
            # Record what type of charater this is.
            if character.islower():
                lowercase_seen = True
            elif character.isupper():
                uppercase_seen = True
            elif character.isnumeric():
                digit_seen = True

            # See if this character is part of a sucessive sequence.
            current_succession_length += 1
            if character == previous_character:
                if current_succession_length == SUCCESSION_LENGTH:
                    successive_characters_seen += 1
                    # Start the count again, as "AAAAAA" should count as 2
                    # successive sequences.
                    current_succession_length = 1
                    previous_character = ""
                else:
                    previous_character = character
            else:
                # Start the count at 1 as this is a new character so the start of its own sequence.
                current_succession_length = 1
                previous_character = character
            
            # Add the character to the previously seen text, and trim to the maximum
            # size if required.
            previous_seen_text += character
            if len(previous_seen_text) > common_password_maximum_length:
                previous_seen_text = previous_seen_text[1:]
            # See if the end of the previous seen text is in the list of common passwords.
            # As an optimisation the passwords are stored according to their last character, so
            # only the entry corresponding to the current password chracter needs to be checked.
            # For simplicity, duplicates are not detected. For example, the text "12344567" will
            # match common passwords "1234", "12345", "123456" and "1234567".
            if character in common_passwords:
                # The passwordds for a character are grouped by length, so go through each length
                # and compare to the most recent text seen of this length to the list of common
                # passwords of this length.
                for password_length, common_passwords_for_length in common_passwords[character].items():
                    if len(previous_seen_text) >= password_length:
                        previous_seen_text_of_length = previous_seen_text[password_length * -1:]
                        if previous_seen_text_of_length in common_passwords_for_length:
                            common_passwords_seen += 1

    # Work out the number of changes needed to satisfy all properties.
    # Try to be somewhat optimal, for example if characters need to be
    # added for length and a digit is missing, assume at least one of the
    # characters added is a digit.
    # This is however assuming that we are not looking for the absolute
    # minimum number of changes, in order to keep things simple. This means
    # that some efficiencies are not checked. For example, "1233212345"
    # will return 2 changes, as it contains the common passwords
    # "123321" and "12345", but it won't detect that actually one
    # change (changing the '1' at position 6) could be made to resolve
    # both issues at the same time.
    number_of_changes = 0

    # Addd characters to bring the password to the minimum length.
    while characters_seen < MINIMUM_LENGTH:
        characters_seen += 1
        number_of_changes += 1
        # Assume that the character added is of a type not already seen.
        if not lowercase_seen:
            lowercase_seen = True
        elif not uppercase_seen:
            uppercase_seen = True
        elif not digit_seen:
            digit_seen = True

    # Delete characters to bring the password to the maximum length.
    # Assume the characters removed are at the end unless they.
    # For simplicity, do not do the optimisation of not removing a
    # character if it is the only one of the type e.g. the only lowercase
    # lettter is the last character in the sequence but it is beyond the
    # maximum length.
    if characters_seen > MAXIMUM_LENGTH:
        number_of_changes += characters_seen - MAXIMUM_LENGTH
    
    # Add one of each type of missing character.
    if not lowercase_seen:
        number_of_changes += 1
    if not uppercase_seen:
        number_of_changes += 1
    if not digit_seen:
        number_of_changes += 1

    # Change one character in each succcessive character sequence.
    number_of_changes += successive_characters_seen

    # Change one character in eachommon password.
    # For simplicity, assume that all common passwords can be changed to a
    # non-common one with exactly one character change.
    number_of_changes += common_passwords_seen

    return number_of_changes


def run_password_check() -> None:
    test_cases = [
        # Secure
        [
            "1377C0d3",
            0
        ],
        [
            "1243586aB",
            0
        ],
        [
            "aB123ccdde",
            0
        ],
        [
            "11224433556677889900112aB",
            0
        ],

        # Too short
        [
            "",
            7
        ],
        [
            "z",
            6
        ],
        [
            "aA1",
            4
        ],

        # Too long
        [
            "1122443355667788990011aB22",
            1
        ],
        [
            "1122443355667788990011aB2244336677",
            9
        ],

        # Only lowercase lettters
        [
            "abcabcabc",
            2
        ],

        # Only uppercase lettters
        [
            "ABCABCABC",
            2
        ],

        # Only digits
        [
            "1122554433",
            2
        ],

        # Missing lowercase letter
        [
            "ABC321GHI",
            1
        ],

        # Missing uppercase letter
        [
            "abc321ghi",
            1
        ],

        # Missing digit
        [
            "abcDEFghi",
            1
        ],

        # Character in sucession
        [
            "123AAAa456",
            1
        ],
        [
            "123AAAAAa456",
            1
        ],
        [
            "123AAAAAAa456",
            2 # 2 Sets of 'AAA'
        ],

        # Common password
        [
            "ab1234AB",
            1
        ],
        [
            "ab1234567AB",
            4
        ],
        [
            "q1w2e3r4t5y6A",
            1
        ],

        # Too short and only digit
        [
            "11224",
            2
        ],
        [
            "112244",
            2
        ],

        # Too short and successive characters
        [
            "11222",
            3
        ],

        # Too short, no letters and successive characters
        [
            "112223",
            3
        ],

        # Too long but successive characters beyond limit
        [
            "11224433556677889900aB112244336666",
            9
        ],

        # Too long but common password beyond limit
        [
            "11224433556677889900aB11224433summer",
            11
        ],

        # Too long but lower and uppercase characters beyond limit
        [
            "1122443355667788990011224433556677aB",
            13
        ],

        # Missing lowercase letter and successive characters
        [
            "123AAA456",
            2
        ],

        # Only digit and successive characters
        [
            "132444567",
            3
        ],

        # Multiple common passwords
        [
            "1Ahellosummer",
            2
        ],

        # Multiple common passwords including overlap
        [
            "aB1233212345",
            3
        ],
        [
            "Aabc123123",
            2
        ],
        [
            "Aabc123123123",
            3
        ],
    ]

    tests_passed = True
    for test_case in test_cases:
        input = test_case[0]
        expected = test_case[1]
        result = _check_password(input)

        test_pass = result == expected
        if not test_pass:
            tests_passed = False

        print("Input: {0}  -  Expected: {1}  -  Output: {2}  -  Pass: {3}".format(str(input), str(expected), str(result), test_pass))
        
    print("Test Results: {0}".format(tests_passed))


def Run() -> None:
    run_password_check()


Run()