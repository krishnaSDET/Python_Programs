def count_substring(string, sub_string):
    counting = 0
    while sub_string in string:
        a=string.find(sub_string)
        breakpoint()
        string=string[a+1:]
        counting += 1
    return counting


ini_str = "ABCDCDC"
 
# Printing initial string
print("Initial string", ini_str)
 
# Finding all permutation
result = []
 
def permute(data, i, length):
    if i == length:
        result.append(''.join(data) )
    else:
        for j in range(i, length):
            # swap
            data[i], data[j] = data[j], data[i]
            #print("before"+str(j))
            permute(data, i + 1, length)
            #breakpoint()
            data[i], data[j] = data[j], data[i]
            #print("after"+str(j))


if __name__ == '__main__':
    #string = input().strip()
    #sub_string = input().strip()
    
    #count = count_substring(string, sub_string)
    permute(list(ini_str), 0, len(ini_str))
    print("Resultant permutations", str(result))
    #print(count)
