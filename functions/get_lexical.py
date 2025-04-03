import Levenshtein

# zisti ci obsahuje slovo z blacklistnutych slov
def contains_word(domain, blacklist):
    domain_name = domain.split('.')[0].lower() 

    with open(blacklist, 'r') as file:
        blacklist_words = file.read().splitlines()

    for word in blacklist_words:
        if word.lower() in domain_name:
            return True
    return False

# ci posledne 2 znaky su "sk" (nie TLD)
def last_bigram_is_sk(domain):
    domain_name = domain.split('.')[0]
    return domain_name[-2:].lower() == 'sk'

# pomery hlasok
def ratios(domain):
    vowels = "aeiouy"
    consonants = "bcdfghjklmnpqrstvwxz"
    nums = "0123456789"
    special_chars = "-_~"

    vowel_count = 0
    consonant_count = 0
    num_count = 0
    special_count = 0
    domain_length = 0

    for char in domain.lower():
        if char in vowels:
            vowel_count += 1

        if char in consonants:
            consonant_count += 1

        if char in nums:
            num_count += 1

        if char in special_chars:
            special_count += 1

        domain_length += 1

    vowel_ratio = round(vowel_count/domain_length, 2)
    consonant_ratio = round(consonant_count/domain_length, 2)
    num_ratio = round(num_count/domain_length, 2)
    special_ratio = round(special_count/domain_length, 2)

    return vowel_ratio, consonant_ratio, num_ratio, special_ratio

# sekvencie hlasok
def sequences(domain):
    vowels = "aeiouy"
    consonants = "bcdfghjklmnpqrstvwxz"
    nums = "0123456789"
    special_chars = "-"

    max_vowel_sequence = 0
    max_consonant_sequence = 0
    max_num_sequence = 0
    max_special_sequence = 0
    vowel_count = 0
    consonant_count = 0
    num_count = 0
    special_count = 0

    for char in domain:
        char = char.lower()

        if char in vowels:
            vowel_count += 1
            consonant_count = num_count = special_count = 0

        elif char in consonants:
            consonant_count += 1
            vowel_count = num_count = special_count = 0

        elif char in nums:
            num_count += 1
            vowel_count = consonant_count = special_count = 0

        elif char in special_chars:
            special_count += 1
            vowel_count = consonant_count = num_count = 0
            
        else:
            vowel_count = consonant_count = num_count = special_count = 0

        
        max_vowel_sequence = max(max_vowel_sequence, vowel_count)
        max_consonant_sequence = max(max_consonant_sequence, consonant_count)
        max_num_sequence = max(max_num_sequence, num_count)
        max_special_sequence = max(max_special_sequence, special_count)

    return max_vowel_sequence, max_consonant_sequence, max_num_sequence, max_special_sequence


def levenshtein_distance(domain, whitelist):
    min_levenshtein = float('inf')
    
    # Levenshtein distance indicates whether there is a similar domain in whitelist = typosquatting detection
    for whitelist_domain in whitelist:
        levenshtein = Levenshtein.distance(domain, whitelist_domain)
        if (min_levenshtein >= levenshtein):
            min_levenshtein = levenshtein
        

    return min_levenshtein