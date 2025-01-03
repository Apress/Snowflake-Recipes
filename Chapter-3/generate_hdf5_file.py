import numpy as np
import h5py
 
def write():
	c_custkey = [101, 102, 103, 104]
	c_mktsegment = ['MACHINERY','BUILDING','BUILDING','FURNITURE']
	
	with h5py.File('customers.hdf5', 'w') as f:
		f.create_dataset('C_CUSTKEY', data = c_custkey)
		f.create_dataset('C_MKTSEGMENT', data = c_mktsegment)

def read():
	with h5py.File('customers.hdf5', 'r') as f:
		d1 = f['C_CUSTKEY']
		d2 = f['C_MKTSEGMENT']

		response = str(d1[:]) + str(d2[:])
		print(response)

write()
read()