class A():
    def __init__(self,a,b):
        self.a =a
        self.b=b
    def add(self):
        return self.a+self.b

class B(A):
    def add(self):
        return self.a+self.b


# class C(B,A):
#     def add(self):
#         return self.a+self.b
c= B(5,6)
print(c.add())