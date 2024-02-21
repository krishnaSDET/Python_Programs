string_value = "ABDEFGABEF"
head =0
tail =0
res = set()
value ={}
# print(string_value[-1])
for i in range(len(string_value)):
    while string_value[i] in res:
        res.remove(string_value[i])
        head = head + 1
    res.add(string_value[i])
    tail =max(tail, i-head+1)
    value[tail] = "".join(res)

print(tail)
print(value[tail])