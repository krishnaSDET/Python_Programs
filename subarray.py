def subarray(arr,n,sum):  
  currentsum = arr[0]  
  begin = 0   
  i = 1  
  while i <= n:   
      while currentsum > sum and begin < i-1:  
           
          currentsum = currentsum - arr[begin]  
          begin = begin + 1  
      if currentsum == sum:  
          print ("Subarray with given sum is between indexes % d and % d"%(begin, i-1))  
          return 1   
      if i < n:  
          currentsum = currentsum + arr[i]  
      i = i + 1  
  print("Subarray with given sum is NOT Found")  
  return 0  

n = 6  
A = [2, 6, 5, 31, 11, 8];
sum = 8;
subarray( A , n , sum)  
