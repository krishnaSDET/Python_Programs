string_value = "ABDEFGABEF"

res = set()
final = {}
for i in range(len(string_value)):
    while string_value[i] in res:
        key = "".join(res)
        final[key] = len(res)
        res.remove(string_value[i])
        print(string_value[i])
    res.add(string_value[i])

print(final)
