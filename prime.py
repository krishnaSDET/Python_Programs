def prime(number,i=2):

   if number ==i:
       return True

   elif number % i==0:
       return False
   return prime(number, i+1)


n=560
if prime(n):
    print("yes")

else:
    print("No")
