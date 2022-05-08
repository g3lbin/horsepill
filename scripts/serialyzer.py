#!/usr/bin/python3
# This script prints a header file for the C language, constructed
# by converting the input file into a byte array

import sys
import os.path

def usage():
    print("Usage:", sys.argv[0], "<filename>")
    exit(1)

if len(sys.argv) < 2:
    usage()

filename = sys.argv[1]
if os.path.isfile(filename) == False:
    usage()

split_list = filename.split("/")
split_len = len(split_list)
name = split_list[split_len - 1].split(".")[0].lower()
name = name.replace('-', '');
name = name.replace(' ', '');
name = name.replace('\\', '');
name = name.replace('?', '');
name = name.replace('!', '');
name = name.replace('+', '');

per_line_items = 12
serialyzed_file = ""
line_items = 0
length = 0
final_tab = False
with open(filename, 'rb') as f:
    print("#ifndef " + name.upper() + "_H")
    print("#define " + name.upper() + "_H")
    print("\nunsigned char " + name + "[] = {")
    serialyzed_file += "\t"
    while 1:
        byte_s = f.read(1)
        if not byte_s:
            break
        byte = f"{byte_s[0]:#0{4}x}"
        serialyzed_file += byte + ", "
        
        length += 1
        line_items += 1
        final_tab = False
        if line_items == per_line_items:
            # remove last space
            serialyzed_file = serialyzed_file[:len(serialyzed_file) - 1]
            # break line
            serialyzed_file += "\n"
            serialyzed_file += "\t"
            line_items = 0
            final_tab = True

garbage_len = 3 if final_tab else 2
serialyzed_file = serialyzed_file[:len(serialyzed_file) - garbage_len]
print(serialyzed_file)
print("};")
print("unsigned int " + name + "_len = " + str(length) + ";")
print("\n#endif")