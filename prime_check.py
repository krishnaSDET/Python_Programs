value =5
flag = False
for i in range(2,5):
    if value % i ==0:
        flag = False
        break;
else:
    print(" %d is prime"%value)
