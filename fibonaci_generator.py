def fibonaci(limit):

    a,b=0,1
    count=0
    while count < limit:
        yield a
        # b = a+b
        # a = b-a
        a,b= b, a+b
        count +=1

for i in fibonaci(5000):
    print(i)