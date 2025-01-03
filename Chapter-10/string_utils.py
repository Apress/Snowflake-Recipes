# Python3 code to count vowel in
# a string using set

def vowel_count(str):
	
	# Initializing count variable to 0
	count = 0
	
	# Creating a set of vowels
	vowels = set("aeiouAEIOU")
	
	count = sum(str.count(vowel) for vowel in vowels)
	
	return count
	

#str = "Test Sentence for Function"
# Test Function Call
#print(vowel_count(str))
