from flask import Flask, request, jsonify
from mimesis import Person
from mimesis.locales import Locale
from mimesis.enums import Gender
import logging

###
# constants and global settings
###
# create flask app
app = Flask(__name__)
# Create a logger
logging.basicConfig(level=logging.INFO)
# create Person singleton
person = Person(Locale.EN)

@app.route('/generate_person_data', methods=['POST'])
def generate_person_data():
    # Get JSON data from request
    data = request.get_json()
    logging.info("Log app started")
    logging.info(data)
    # Check if the 'data' key exists in the received JSON
    if 'data' not in data:
        return jsonify({'error': 'Missing data key in request'}), 400

    # Extract the 'data' list from the received JSON
    data_list = data['data']
    
    # Initialize a list to store converted values
    generated_data = []
    
    logging.info("size of the batch: %d", len(data_list))
    logging.info("processing each row")
    
    # Iterate over each item in 'data_list'
    for item in data_list:
        logging.info(item)
        # Check if the item is a list with at least 3 elements
        if not isinstance(item, list) or len(item) < 3:
            return jsonify({'error': 'Invalid data format'}), 400
                
        gender = item[1] #'gender'
        email_domain = item[2] #'email_domain'
        is_employed = item[3] #'is_employed'

        if gender=='F':
            name = person.full_name(gender=Gender.FEMALE)
        elif gender=='M':
            name = person.full_name(gender=Gender.MALE)
        else:
            name = person.full_name()
        
        if is_employed=='true':
            occupation = person.occupation()
        else:
            occupation = 'unemployed'
        
        university = person.university()
        
        if email_domain=='gmail':
            email = person.email(domains=["gmail.com"])
        elif email_domain=='outlook':
            email = person.email(domains=["outlook.com"])
        else:
            email = person.email()
        
        generated_data.append([item[0], [name, occupation, university, email] ])
        
    logging.info(generated_data)
    logging.info("Log app ended")
    # Return the converted data as JSON
    return jsonify({'data': generated_data})

@app.route('/test_generate_person_data', methods=['POST'])
def test_generate_person_data():
    

    name = person.full_name()
    occupation = 'unemployed'
    university = person.university()
    email = person.email()
    
    # Return the converted data as JSON
    return jsonify({'data': [[0, [name, occupation, university, email] ]]})


if __name__ == '__main__':
    app.run(debug=True)