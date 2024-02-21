def outer(func):
    def inner(name):
        result = "hellow" +func(name)
        return (result)

    return inner

@outer
def hello(name):
    return name + "good morning"



print(hello("john"))
