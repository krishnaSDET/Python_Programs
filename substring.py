data='abcdcdc'
data1='abcdcdc'
dict1 ={}
while len(data) !=0:	
	string = data[0]
	for j in range(1,len(data)):
		string = string + data[j]
		if len(string) >2 and data1.find(string):
			if string not in dict1.keys():
				dict1[string]=1
			else:
				dict1[string]=dict1[string]+1
	data=data[1:]

print (dict1)
