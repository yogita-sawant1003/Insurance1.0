from flask import Flask, request, jsonify, render_template, redirect, url_for, session
import requests
import pandas as pd
import numpy as np
import pickle
from datetime import datetime
import uuid
import os
import json
import hmac
import hashlib
import base64
import pyotp
import qrcode

from dotenv import load_dotenv


load_dotenv()
# Generate a secure random key
secret_key = secret_key = base64.b32encode(os.urandom(20)).decode()  # Use 20 bytes for a 160-bit key



app = Flask(__name__)
app.secret_key = secret_key  # Use the generated secret key



# Load the trained model
model2_path='models/model.pkl'
model_path = 'models/driver_model1.pkl'
encoder_path = 'models/label_encoder_driver.pkl'
scaler_path = 'models/scaler_driver.pkl'
model3_path ='models/multi_task_model.pkl'
scaler2_path ='models/multi_task_scaler.pkl'
with open(model2_path, 'rb') as model_file:
    model= pickle.load(model_file)
# Load the model
with open(model_path, 'rb') as model_file:
    model_driver = pickle.load(model_file)

# Load the label encoder
with open(encoder_path, 'rb') as encoder_file:
    label_encoder = pickle.load(encoder_file)

# Load the scaler
with open(scaler_path, 'rb') as scaler_file:
    scaler = pickle.load(scaler_file)
with open(scaler2_path, 'rb') as scaler_file:
    scaler_DTC = pickle.load(scaler_file)
with open(model3_path,'rb') as model_file:
    model_DTC=pickle.load(model_file)     
with open('label_encoder_DTC.pkl', 'rb') as le_file:
    le = pickle.load(le_file)
# Proxy configuration



API_KEY_LIGHTHOUSE = os.getenv('API_KEY_LIGHTHOUSE')
API_KEY_VIRUSTOTAL = os.getenv('API_KEY_VIRUSTOTAL')

# Function to scan a file using VirusTotal
def scan_file_with_virustotal(file_path):
    url = 'https://www.virustotal.com/api/v3/files'
    headers = {
        'x-apikey': API_KEY_VIRUSTOTAL
    }
    try:
        with open(file_path, 'rb') as file:
            response = requests.post(url, headers=headers, files={'file': file})
            response.raise_for_status()
            scan_data = response.json()
            scan_id = scan_data['data']['id']
            return scan_id
    except requests.RequestException as e:
        raise Exception(f"Error scanning file with VirusTotal: {e}")

# Function to check the scan results from VirusTotal
def get_scan_results(scan_id):
    url = f'https://www.virustotal.com/api/v3/analyses/{scan_id}'
    headers = {
        'x-apikey': API_KEY_VIRUSTOTAL
    }
    try:
        response = requests.get(url, headers=headers)
        response.raise_for_status()
        scan_results = response.json()
        # Check if the file is malicious based on the scan results
        malicious = scan_results['data']['attributes']['stats']['malicious']
        return malicious
    except requests.RequestException as e:
        raise Exception(f"Error getting scan results from VirusTotal: {e}")

# Function to download a file from Lighthouse using CID
def download_from_lighthouse(cid):
    lighthouse_url = f'https://gateway.lighthouse.storage/ipfs/{cid}'
    headers = {
        'Authorization': f'Bearer {API_KEY_LIGHTHOUSE}'
    }
    try:
        response = requests.get(lighthouse_url, headers=headers)
        response.raise_for_status()
        return response.content
    except requests.RequestException as e:
        raise Exception(f"Error downloading file from Lighthouse: {e}")

# Function to upload a file to Lighthouse and get the CID
def upload_to_lighthouse(file_path):
    url = 'https://node.lighthouse.storage/api/v0/add'
    headers = {
        'Authorization': f'Bearer {API_KEY_LIGHTHOUSE}'
    }
    try:
        with open(file_path, 'rb') as file:
            response = requests.post(url, files={'file': file}, headers=headers)
            response.raise_for_status()
            return response.json()['Hash']
    except requests.RequestException as e:
        raise Exception(f"Error uploading file to Lighthouse: {e}")

# Function to generate a digital signature
def generate_signature(data):
    # Create a digital signature using HMAC with SHA256
    message = json.dumps(data, sort_keys=True).encode()
    signature = hmac.new(secret_key.encode(), message, hashlib.sha256).hexdigest()
    return signature

# Function to verify the digital signature
def verify_signature(data, provided_signature):
    # Generate the expected signature
    expected_signature = generate_signature(data)
    # Use hmac.compare_digest to securely compare signatures
    return hmac.compare_digest(expected_signature, provided_signature)

# Function to process the file and make predictions
def process_and_predict(file_content):
    # Save the file content to a local file
    file_path = 'temp_file.xlsx'
    with open(file_path, 'wb') as file:
        file.write(file_content)

    # Scan the file with VirusTotal
    scan_id = scan_file_with_virustotal(file_path)
    malicious = get_scan_results(scan_id)
    
    # If the file is flagged as malicious, stop processing
    if malicious > 0:
        os.remove(file_path)
        raise Exception("The uploaded file is flagged as malicious.")

    # Read the Excel file
    df = pd.read_excel(file_path)
    
    # Define required columns for engine health prediction
    required_columns = ['Engine RPM', 'Lub oil pressure', 'Fuel pressure', 'Coolant pressure', 'Lub oil temperature', 'Coolant temp']
    
    # Case 1: If the file contains the required columns for engine health
    if all(col in df.columns for col in required_columns):
        # Calculate the average of each parameter
        avg_data = {
            'engine_rpm': df['Engine RPM'].mean(),
            'oil_pressure': df['Lub oil pressure'].mean(),
            'fuel_pressure': df['Fuel pressure'].mean(),
            'coolant_pressure': df['Coolant pressure'].mean(),
            'oil_temperature': df['Lub oil temperature'].mean(),
            'coolant_temperature': df['Coolant temp'].mean()
        }
    
        # Prepare the input for the model using the averaged data
        input_data = np.array([[avg_data['engine_rpm'], avg_data['oil_pressure'], avg_data['fuel_pressure'], avg_data['coolant_pressure'], avg_data['oil_temperature'], avg_data['coolant_temperature']]])
    
        # Predict engine health status
        
        prediction = model.predict(input_data)
        print(f"Prediction: {prediction}")
        print(model.classes_)  
        engine_health_status = int(prediction[0])
    
        # Generate unique vehicle ID and timestamp
        vehicle_id = uuid.uuid4().int % 10**8
        timestamp = int(datetime.now().strftime("%Y%m%d%H%M"))
    
        # Prepare the result
        result = {
            "VEHICLEID": vehicle_id,
            "ENGINEHEALTH": engine_health_status,
            "TIMESTAMP": timestamp
        }
    
        # Generate a digital signature for the result
        signature = generate_signature(result)
    
        # Save the result as an Excel file
        results_df = pd.DataFrame([result])
        results_file_path = 'results_engine.xlsx'
        results_df.to_excel(results_file_path, index=False)
    
        # Upload the results file to Lighthouse and get the CID
        results_cid = upload_to_lighthouse(results_file_path)
    
        # Clean up temporary files
        os.remove(file_path)
        os.remove(results_file_path)
    
        # Save result as a JSON file and upload to Lighthouse
        result_json_path = 'result.json'
        with open(result_json_path, 'w') as json_file:
            json.dump(result, json_file)
    
        result_json_cid = upload_to_lighthouse(result_json_path)
        os.remove(result_json_path)
    
        return result, results_cid, result_json_cid, signature
    
    # Case 2: Predict driver behavior if engine health columns are missing
    else:

    # Convert the data to a NumPy array and reshape for the model
     new_data = df.values

    # Debug: Print the input data shape
    print(f"Input data shape: {new_data.shape}")
    
    # Check if the input data matches the expected number of features
    

    # Scale the input data
    new_data_scaled = scaler.transform(new_data)

    # Make a prediction using the model
    predicted_class = model_driver.predict(new_data_scaled)

    # Convert numerical prediction back to the original categorical label
    predicted_label = label_encoder.inverse_transform(predicted_class)

    # Debug: Print the raw prediction and the label
    print(f"Raw model predictions: {predicted_class}")
    print(f"Predicted driver behavior: {predicted_label[0]}")
    
    # Prepare result as a dictionary with vehicle ID, behavior, and timestamp
    vehicle_id = uuid.uuid4().int % 10**8
    timestamp = int(datetime.now().strftime("%Y%m%d%H%M"))

    result = {
        "VEHICLEID": vehicle_id,
        "BEHAVIOR": predicted_label[0],  # Correct behavior label
        "TIMESTAMP": timestamp
    }

    # Generate a digital signature for the result
    signature = generate_signature(result)

    # Convert the result to a DataFrame and save to an Excel file
    results_df = pd.DataFrame([result])
    results_file_path = 'results_driver.xlsx'
    results_df.to_excel(results_file_path, index=False)

    # Upload the results Excel file to Lighthouse and get the CID
    results_cid = upload_to_lighthouse(results_file_path)
    
    # Clean up the Excel file after uploading
    if os.path.exists(results_file_path):
        os.remove(results_file_path)
    
    # Save the result as a JSON file and upload it to Lighthouse
    result_json_path = 'result.json'
    with open(result_json_path, 'w') as json_file:
        json.dump(result, json_file)

    # Upload the JSON file to Lighthouse and get the CID
    result_json_cid = upload_to_lighthouse(result_json_path)

    # Clean up the JSON file after uploading
    if os.path.exists(result_json_path):
        os.remove(result_json_path)

    # Return the result, CIDs, and signature
    return result, results_cid, result_json_cid, signature

def generate_totp_setup():
    totp = pyotp.TOTP(secret_key)
    provisioning_uri = totp.provisioning_uri(name='FlaskApp', issuer_name='YourAppName')
    
    qr = qrcode.QRCode()
    qr.add_data(provisioning_uri)
    qr.make(fit=True)
    
    img = qr.make_image(fill='black', back_color='white')
    qr_code_path = 'C:/bla/InsuranceFrontend/static/qr_code.png'
    img.save(qr_code_path)
    
    return qr_code_path

# Function to verify the TOTP code
def verify_totp(code):
    totp = pyotp.TOTP(secret_key)
    return totp.verify(code)

def alternate(file_content):
    # Save the file content to a local file
    file_path = 'temp_file.xlsx'
    with open(file_path, 'wb') as file:
        file.write(file_content)

    # Scan the file with VirusTotal
    scan_id = scan_file_with_virustotal(file_path)
    malicious = get_scan_results(scan_id)

    # If the file is flagged as malicious, stop processing
    if malicious > 0:
        os.remove(file_path)
        return {"error": "The uploaded file is flagged as malicious."}, 400

    # Read the Excel file
    try:
        df = pd.read_excel(file_path)
    except Exception as e:
        os.remove(file_path)
        return {"error": "Failed to read the Excel file. " + str(e)}, 400

    # Define required columns for engine health prediction
    required_columns = ['mileage', 'temperature', 'pressure', 'rpm']

    # Check if all required columns are present
    if not all(col in df.columns for col in required_columns):
        os.remove(file_path)
        return {"error": "The uploaded file is missing required columns."}, 400

    # Process data and make predictions
    try:
        # Extract data for prediction
        new_data = df[required_columns].values

        # Scale data and make predictions
        new_data_scaled = scaler_DTC.transform(new_data)
        predictions = model_DTC.predict(new_data_scaled)

        # Prepare results
        results = []
        for i, (pred_failure, pred_component) in enumerate(predictions):
            component_decoded = le.inverse_transform([pred_component])[0]
            failure_msg = (
                f"The component is likely to fail in the next 1000 miles. The likely cause is: {component_decoded}."
                if pred_failure == 1 else
                "The component is unlikely to fail."
            )

            # Generate unique vehicle ID and timestamp
            vehicle_id = uuid.uuid4().int % 10**8
            timestamp = int(datetime.now().strftime("%Y%m%d%H%M"))

            # Store result
            result = {
                "VEHICLEID": vehicle_id,
                "MESSAGE": failure_msg,
                "TIMESTAMP": timestamp
            }
            results.append(result)

        # Generate a digital signature for the results
        signature = generate_signature(results)

        # Save the results to an Excel file
        results_df = pd.DataFrame(results)
        results_file_path = 'results_engine.xlsx'
        results_df.to_excel(results_file_path, index=False)

        # Upload the results file to Lighthouse and get the CID
        results_cid = upload_to_lighthouse(results_file_path)

        # Save results as a JSON file and upload to Lighthouse
        result_json_path = 'result.json'
        with open(result_json_path, 'w') as json_file:
            json.dump(results, json_file)

        result_json_cid = upload_to_lighthouse(result_json_path)

        # Clean up temporary files
        os.remove(file_path)
        os.remove(results_file_path)
        os.remove(result_json_path)

        # Return the results, CIDs, and signature
        return {
            "results": results,
            "results_cid": results_cid,
            "result_json_cid": result_json_cid,
            "signature": signature
        }
    except Exception as e:
        os.remove(file_path)
        return {"error": "An error occurred during prediction. " + str(e)}, 500


@app.route('/')
def home():
    if not session.get('authenticated'):
        return redirect(url_for('setup_2fa'))
    return render_template('index.html')

@app.route('/setup_2fa')
def setup_2fa():
    qr_code_path = generate_totp_setup()
    return render_template('setup_2fa.html', qr_code_path=qr_code_path)

@app.route('/verify_2fa', methods=['POST'])
def verify_2fa():
    code = request.form.get('code')
    if not verify_totp(code):
        return jsonify({"error": "Invalid code"}), 400
    
    session['authenticated'] = True
    return redirect(url_for('home'))

@app.route('/process_file', methods=['POST'])
def process_file():
    if not session.get('authenticated'):
        return redirect(url_for('setup_2fa'))

    cid = request.json.get('cid')
    if not cid:
        return jsonify({"error": "No CID provided"}), 400

    try:
        file_content = download_from_lighthouse(cid)
        results, results_cid, result_json_cid, signature = process_and_predict(file_content)
        return jsonify({"results": results, "results_cid": results_cid, "result_json_cid": result_json_cid, "signature": signature})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/upload_file', methods=['POST'])
def upload_file():
    if not session.get('authenticated'):
        return redirect(url_for('setup_2fa'))

    file = request.files.get('file')
    if not file:
        return jsonify({"error": "No file provided"}), 400

    try:
        file_path = 'temp_upload.xlsx'
        file.save(file_path)
        scan_id = scan_file_with_virustotal(file_path)
        malicious = get_scan_results(scan_id)
        if malicious > 0:
            os.remove(file_path)
            raise Exception("The uploaded file is flagged as malicious.")
        cid = upload_to_lighthouse(file_path)
        os.remove(file_path)
        return jsonify({"cid": cid})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/alternate_file', methods=['POST'])
def alternate_file():
    print(request.json)  # Print the JSON data received in the request to check if it's valid
    if not session.get('authenticated'):
        return redirect(url_for('setup_2fa'))

    cid = request.json.get('cid')
    if not cid:
        return jsonify({"error": "No CID provided"}), 400

    try:
        # Download file content from Lighthouse using CID
        file_content = download_from_lighthouse(cid)
        if not file_content:
            return jsonify({"error": "Failed to retrieve file content from Lighthouse"}), 500

        # Process file content with the alternate function
        result = alternate(file_content)
        
        # Check for any error returned by the alternate function
        if isinstance(result, tuple) and "error" in result[0]:
            return jsonify(result[0]), result[1]  # Return the error message and status code

        # If successful, return the result
        return jsonify(result)
        
    except Exception as e:
        return jsonify({"error": str(e)}), 500

 

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)