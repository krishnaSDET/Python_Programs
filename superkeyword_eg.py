class A:
    def age(self):
        print("Age is 21")
class B:
    def age(self):
        print("Age is 23")
class C(A, B):
    def age(self):
        super(C,self).age()


c = C()
print(C.__mro__)
print(C.mro())
print(c.age())