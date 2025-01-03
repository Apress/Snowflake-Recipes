create or replace function python_read_hdf5(file string)
    returns string
    language python
    runtime_version = 3.8
    packages = ('snowflake-snowpark-python','h5py')
    handler = 'read_file'
as
$$
from snowflake.snowpark.files import SnowflakeFile
from io import BytesIO
import h5py
def read_file(file_path):
    response = ""
    with SnowflakeFile.open(file_path, 'rb') as file:
        f = BytesIO(file.readall())
        f =  h5py.File(f)
        d1 = f['C_CUSTKEY']
        d2 = f['C_MKTSEGMENT']
        
        response = str(d1[:]) + str(d2[:])
        return response
$$;

