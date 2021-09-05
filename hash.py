
def adler32(text_in_string: str) -> int:
    ADLER_MOD = 65521
    a = 1
    b = 0
    for char in text_in_string:
        a = (a + ord(char)) % ADLER_MOD
        b = (b + a) % ADLER_MOD
    #print(a)
    #print(b)
    return (b << 16) | a


#print(adler32("hello"))