# ------------------------
#  Substitution Ciphers
# ------------------------

from math import sqrt
from utilities import create_table
from utilities import print_matrix
from utilities import get_positions
from utilities import insert_positions
from utilities import clean_text
from utilities import index_2d
from utilities import is_plaintext
from utilities import text_to_words
from utilities import text_to_blocks
from utilities import dictionary_to_list


class Wheatstone:
    DEFAULT_KEY = (0, 25, 'BR')
    CORNERS = ['BR', 'BL', 'TR', 'TL']
    BASE = """abcdefghijklmnopqrstuvxyzABCDEFGHIJKLMNOPQRSTUVXYZ0123456789!"#$%&'()*+,-./:;<=>?@[\]^_`{|}~"""
    DICT_FILE = 'engmix.txt'

    def __init__(self, key=DEFAULT_KEY, pad='q'):
        if self.valid_key(key):
            if type(pad) == str and len(pad) == 1:
                self.__key = key
                self.set_pad(pad)
            else:
                self.__key = self.__key
                self.__pad = 'q'
        else:
            if type(pad) == str and len(pad) == 1:
                self.__key = self.DEFAULT_KEY
                self.set_pad(pad)
            else:
                self.__key = self.DEFAULT_KEY
                self.__pad = 'q'

        pass

    def get_base(self):
        x = self.BASE[self.get_key()[0]:self.get_key()[0] + self.get_key()[1]]
        return x

    def set_key(self, key):
        if Wheatstone.valid_key(key):
            self.__key = key
            return True
        else:
            self.__key = self.DEFAULT_KEY
            return False

    def set_pad(self, pad):
        if type(pad) == str and len(pad) == 1 and self.get_base().count(pad) != 0:
            self.__pad = pad
            return True
        else:
            self.__pad = self.BASE[self.__key[0] + self.__key[1] - 1]
            return False

    def get_key(self):
        return (self.__key[0], self.__key[1], self.__key[2])

    def get_pad(self):
        return self.__pad

    @staticmethod
    def valid_key(key):
        if type(key) != tuple or len(key) != 3:
            return False
        if type(key[0]) != int or type(key[1]) != int:
            return False
        if key[0] < 0 or key[1] < 0:
            return False
        if type(key[2]) == str:
            if key[2] != 'BR' and key[2] != 'BL' and key[2] != 'TL' and key[2] != 'TR':
                return False
        else:
            return False
        if (key[0] + key[1]) < len(Wheatstone.BASE) + 1:
            if sqrt(key[1]) != int(sqrt(key[1])):
                return False
        else:
            return False

        return True

    #@property
    def get_table(self):
        s = int(sqrt(self.get_key()[1]))
        table = create_table(s, s, '')
        r = 0
        c = 0
        counter_r = 0
        sss = 0
        if self.get_key()[2] == 'TL':
            r = 0
            c = 0
            sss = 1
            counter_r = 1
        elif self.get_key()[2] == 'TR':
            r = 0
            c = s - 1
            sss = -1
            counter_r = 1
        elif self.get_key()[2] == 'BL':
            r = s - 1
            c = 0
            sss = 1
            counter_r = -1
        else:
            r = s - 1
            c = s - 1
            sss = -1
            counter_r = -1
        for_tt = self.get_key()[1]

        while -1 < r < s:
            for i in range(s):
                table[r][c] = self.get_base()[self.get_key()[1] - for_tt]
                c = c + sss
                for_tt = for_tt - 1
            sss = -sss
            c = c + sss
            r = r + counter_r
        return table

    def print_table(self):
        s = int(sqrt(self.get_key()[1]))
        for i in range(s):
            t = self.get_table()
            for j in range(s):
                print(t[i][j], end=' ')
            print()

    def __str__(self):
        sttable = ''
        for i in range(int(sqrt(self.get_key()[1]))):
            for j in range(int(sqrt(self.get_key()[1]))):
                if i == int(sqrt(self.__key[1] - 1)) and j == int(sqrt(self.__key[1] - 1)):
                    sttable = sttable + self.get_table()[i][j]
                    break
                sttable = sttable + self.get_table()[i][j] + ' '
        sttable = text_to_blocks(sttable, int(sqrt(self.__key[1]))*2)
        x = "Wheatstone Playfair Cipher:key = {}, pad = {}\n{}".format(self.get_key(), self.get_pad(), '\n'.join(map(str, sttable)))
        return x

    def get_unused_chars(self):
        x = self.BASE[:self.get_key()[0]] + self.BASE[self.get_key()[1] + self.get_key()[0]:]
        x = list(x)
        x.append(' ')
        x.append('\n')
        x.append('\t')
        return x

    def preprocess_plaintext(self, plaintext):
        # plaintext = list(plaintext)
        # for w -->vv

        plaintext = plaintext.replace('w', 'vv')
        plaintext = plaintext.replace('W', 'VV')
        positions = get_positions(plaintext, ''.join(self.get_unused_chars()))
        plaintext = clean_text(plaintext, ''.join(self.get_unused_chars()))
        spaces = get_positions(plaintext, ' ')
        plaintext = clean_text(plaintext, ' ')
        # print(plaintext)
        # check if len(txt) == even
        if len(plaintext) % 2 != 0:
            plaintext = plaintext + self.get_pad()
        # x X

        plaintext = list(plaintext)
        for i in range(0, len(plaintext), 2):
            if i + 1 == len(plaintext):
                break
            if plaintext[i] == plaintext[i + 1]:
                if plaintext[i + 1].isupper():
                    plaintext[i + 1] = 'X'

                elif plaintext[i + 1].islower():
                    plaintext[i + 1] = 'x'
                else:
                    plaintext[i + 1] = 'x'
        plaintext = ''.join(plaintext)
        plaintext = insert_positions(plaintext, spaces)
        plaintext = insert_positions(plaintext, positions)
        return plaintext

    def encrypt(self, plaintext):
        plaintext = self.preprocess_plaintext(plaintext)
        table = self.get_table()
        positions = get_positions(plaintext, ''.join(self.get_unused_chars()))
        plaintext = clean_text(plaintext, ''.join(self.get_unused_chars()))
        spaces = get_positions(plaintext, ' ')
        plaintext = clean_text(plaintext, ' ')
        plaintext = list(plaintext)
        for i in range(0, len(plaintext), 2):
            tst1 = index_2d(table, plaintext[i])
            tst2 = index_2d(table, plaintext[i + 1])
            # Case1 : If same row
            if tst1[0] == tst2[0]:
                plaintext[i] = table[tst1[0]][int((tst1[1] + 1) % sqrt(self.__key[1]))]
                plaintext[i + 1] = table[tst2[0]][int((tst2[1] + 1) % sqrt(self.__key[1]))]
            # Case2 : If same Col
            elif tst1[1] == tst2[1]:
                plaintext[i] = table[int((tst1[0] + 1) % sqrt(self.__key[1]))][tst1[1]]
                plaintext[i + 1] = table[int((tst2[0] + 1) % sqrt(self.__key[1]))][tst2[1]]
            # Case3 : Square
            else:
                plaintext[i] = table[tst1[0]][tst2[1]]
                plaintext[i + 1] = table[tst2[0]][tst1[1]]

        plaintext = ''.join(plaintext)
        plaintext = insert_positions(plaintext, spaces)
        plaintext = insert_positions(plaintext, positions)
        return plaintext

    def restore_word(self, word, dict_list):
        if is_plaintext(word, dict_list):
            return word
        for i in range(0,len(word),2):
            if i == len(word)-1:
                break
            if word[i+1] == chr(ord(word[i])+32) or word[i+1] == chr(ord(word[i])-32):
                word = word[0:i+1] + word[i] + word[i+2:]

        positions = get_positions(word, ''.join(self.get_unused_chars()))
        word = clean_text(word, ''.join(self.get_unused_chars()))
        word = list(word)
        for i in range(0, len(word), 2):
            if i == len(word)-1:
                break
            if word[i+1] == 'x' or word[i+1] == 'X':
                word[i+1] = word[i]
        word = ''.join(word)
        word = insert_positions(word, positions)
        word = word.replace('VV', 'W')
        word = word.replace('vv', 'w')
        return word

    def restore_plaintext(self, text):
        dd = dictionary_to_list(self.DICT_FILE)
        for i in range(len(text)):
            if text[-1] == self.get_pad():
                text = text[0:len(text)-1]
            else:
                continue
        list_4_word = []
        i = 0
        txt = ''
        while True:
            if len(text) == i:
                txt = self.restore_word(txt, dd)
                list_4_word.append(txt)
                break
            if not text[i].isalnum():
                if text[i] == ' ':
                    txt = self.restore_word(txt, dd)
                    list_4_word.append(txt+' ')
                    txt = ''
                    i += 1
                    continue
                else:
                    txt = self.restore_word(txt, dd)
                    txt += text[i]
                    list_4_word.append(txt)
                    txt = ''
                    i += 1
                    continue
            txt += text[i]
            i += 1
        plaintext = ''
        for i in range(len(list_4_word)):
            plaintext += list_4_word[i]
        positions = get_positions(plaintext, ''.join(self.get_unused_chars()))
        #space = get_positions(plaintext, ' ')
        #clean_text(plaintext,' ')
        plaintext = clean_text(plaintext, ''.join(self.get_unused_chars()))
        lst = text_to_blocks(plaintext, 2, False, '')
        #print(lst)
        plaintext = ''
        for i in range(len(lst)):
            if len(lst[i]) != 2:
                plaintext += lst[i]
                continue
            if lst[i][1] == 'x' or lst[i][1] == 'X':
                lst[i] = lst[i][0] * 2
                plaintext += lst[i]
            else:
                plaintext += lst[i]
                continue
        plaintext = insert_positions(plaintext, positions)
        #plaintext = insert_positions(plaintext,space)
        return plaintext
    def decrypt(self, ciphertext):
        d = dictionary_to_list('engmix.txt')
        unused = ''.join(self.get_unused_chars())
        p = get_positions(ciphertext, unused)
        ciphertext = clean_text(ciphertext, unused)
        ciphertext = list(ciphertext)
        table = self.get_table()
        for i in range(0, len(ciphertext), 2):
            if i == len(ciphertext) - 1:
                break

            if index_2d(table, ciphertext[i])[0] == index_2d(table, ciphertext[i+1])[0]:
                ciphertext[i] = table[index_2d(table, ciphertext[i])[0]][int((index_2d(table, ciphertext[i])[1]-1)%sqrt(self.get_key()[1]))]
                ciphertext[i+1] = table[index_2d(table, ciphertext[i+1])[0]][int((index_2d(table, ciphertext[i+1])[1]-1)%sqrt(self.get_key()[1]))]
            elif index_2d(table, ciphertext[i])[1] == index_2d(table, ciphertext[i+1])[1]:
                ciphertext[i] = table[int((index_2d(table, ciphertext[i])[0] - 1)%sqrt(self.get_key()[1]))][index_2d(table, ciphertext[i])[1]]
                ciphertext[i + 1] = table[int((index_2d(table, ciphertext[i + 1])[0] - 1) % sqrt(self.get_key()[1]))][index_2d(table, ciphertext[i + 1])[1]]
            else:
                col0 = index_2d(self.get_table(), ciphertext[i])[1]
                col1 = index_2d(self.get_table(), ciphertext[i+1])[1]
                ciphertext[i] = self.get_table()[index_2d(self.get_table(), ciphertext[i])[0]][col1]
                ciphertext[i + 1] = self.get_table()[index_2d(self.get_table(), ciphertext[i+1])[0]][col0]

        ciphertext = ''.join(ciphertext)
        ciphertext = ciphertext.replace(' ', '')
        ciphertext = insert_positions(ciphertext, p)
        if is_plaintext(ciphertext, d):
            return ciphertext
        else:
            plaintext = self.restore_plaintext(ciphertext)
            return plaintext
    @staticmethod
    def cryptanalyze(ciphertext, args=[None, None, None]):
        dict = dictionary_to_list('engmix.txt')
        st = 0
        size = 0
        corner = ''
        plaintext = ''
        m = 0
        ind = 0
        if args.count(None) != 0:
            if args[0] is not None:
                st = args[0]
            else:
                st = 0
            if args[1] is not None:
                size = args[1]
            else:
                m = Wheatstone.BASE.index(max(ciphertext))
                ind = m - st
                ind = round(sqrt(ind)+0.4)
                size = ind*ind
            if args[2] is not None:
                corner = args[2]
            else:
                corner = 'BL'
        key = [st, size, corner]
        while True:
            c_a = Wheatstone(tuple(key))
            if corner == args[2]:
                plaintext = c_a.decrypt(ciphertext)
                if is_plaintext(plaintext, dict, 0.8):
                    return tuple(key), plaintext
            else:

                key = [st, size, 'TL']
                c_a.set_key(tuple(key))
                plaintext = c_a.decrypt(ciphertext)
                if is_plaintext(plaintext, dict, 0.8):
                    return key, plaintext
                key = [st, size, 'BL']
                c_a.set_key(tuple(key))
                plaintext = c_a.decrypt(ciphertext)
                if is_plaintext(plaintext, dict, 0.8):
                    return tuple(key), plaintext
                key = [st, size, 'BR']
                c_a.set_key(tuple(key))
                plaintext = c_a.decrypt(ciphertext)
                if is_plaintext(plaintext, dict, 0.8):
                    return tuple(key), plaintext
                key = [st, size, 'TR']
                c_a.set_key(tuple(key))
                plaintext = c_a.decrypt(ciphertext)
                if is_plaintext(plaintext, dict, 0.8):
                    return tuple(key), plaintext
                corner = 'BL'
            if args[0] is None:
                st += 1
            elif args[1] is None:
                ind += 1
                size = ind * ind
            key = [st, size, corner]
        return '', ''

