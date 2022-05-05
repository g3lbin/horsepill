#!/usr/bin/python3

filename = "extractor.sh"
per_line_items = 12

serialyzed_file = ""
line_items = 0
length = 0
with open(filename, 'rb') as f:
    while 1:
        byte_s = f.read(1)
        if not byte_s:
            break
        byte = f"{byte_s[0]:#0{4}x}"
        serialyzed_file += byte + ", "
        
        length += 1
        line_items += 1
        if line_items == per_line_items:
            # remove last space
            serialyzed_file = serialyzed_file[:len(serialyzed_file) - 1]
            # break line
            serialyzed_file += "\n"
            line_items = 0

serialyzed_file = serialyzed_file[:len(serialyzed_file) - 2]
print(serialyzed_file)
print("\n\n", "length:", length)
