def outer_function():
  x = 10
  def inner_function():
     nonlocal x
     x += 1
     print(x)
  return inner_function

closure = outer_function()
closure()
