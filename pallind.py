import pdb
data="ababa"
pal=""
for nos,val in enumerate(list(data)):
	pal=pal+val
	
	print(pal)
	
	for val1 in list(data[nos+1:]):
		pal= pal+val1
		if pal==pal[::-1]:
			print(pal)
	pal=""
