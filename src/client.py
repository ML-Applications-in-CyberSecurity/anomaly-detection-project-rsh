import socket
import json
import pandas as pd
import joblib
import csv
import datetime


HOST = 'localhost'
PORT = 9999

model = joblib.load("anomaly_model.joblib")


# Initialize CSV file
with open('anomalies.csv', 'w', newline='') as f:
    writer = csv.writer(f)
    writer.writerow(['Timestamp', 'Data', 'Label', 'Reason' , 'Confidence'])

def pre_process_data(data):
    # Convert data to DataFrame for model prediction
    df = pd.DataFrame([data])
    # One-hot encode the 'protocol' column, matching training preprocessing
    df_processed = pd.get_dummies(df, columns=['protocol'], drop_first=True)
    # Ensure all expected columns are present (e.g., protocol_UDP)
    expected_columns = ['src_port', 'dst_port', 'packet_size', 'duration_ms', 'protocol_UDP']
    for col in expected_columns:
        if col not in df_processed.columns:
            df_processed[col] = 0
    # Reorder columns to match training data
    df_processed = df_processed[expected_columns]
    return df_processed.values

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((HOST, PORT))
    buffer = ""
    print("Client connected to server.\n")

    while True:
        chunk = s.recv(1024).decode()
        if not chunk:
            break
        buffer += chunk

        while '\n' in buffer:
            line, buffer = buffer.split('\n', 1)
            try:
                data = json.loads(line)
                print(f'Data Received:\n{data}\n')

                processed_data = pre_process_data(data)
                prediction = model.predict(processed_data)
                confidence = -model.decision_function(processed_data)[0]  # Negative score = anomaly likelihood
                is_anomaly = prediction[0] == -1

                import together
                together.api_key = "tgp_v1_l0t2pUMNzSPcB-LkOHrxWafVfkGnBkVD2dh9wbmNwKY"
                if is_anomaly:
                    # Prepare message for Together AI
                    messages = [
                        {
                            "role": "system",
                            "content": "You are a network security expert. Based on the network traffic data, identify if there is an anomaly. If there is, provide a short label and a detailed reason."
                        },
                        {
                            "role": "user",
                            "content": f"""Given the following network traffic data:
                            {data}
                            Please respond in this exact format:
                            Label: <short label summarizing the type of anomaly>  
                            Reason: <detailed explanation why it is anomalous>"""
                        }
                    ]
                    
                    # Send request to Together AI
                    client = together.Together(api_key="tgp_v1_l0t2pUMNzSPcB-LkOHrxWafVfkGnBkVD2dh9wbmNwKY")
                    response = client.chat.completions.create(
                        model="mistralai/Mistral-7B-Instruct-v0.1",
                        messages=messages,
                        stream=False
                        )
                    # Extract label and reason
                    llm_output = response.choices[0].message.content
                    # Parse LLM output (assuming it returns "Label: ... Reason: ...")
                    label = llm_output.split("Reason:")[0].replace("Label:", "").strip()
                    reason = llm_output.split("Reason:")[1].strip() if "Reason:" in llm_output else llm_output

                    #log to CSV
                    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                    with open('anomalies.csv', 'a', newline='') as f:
                        writer = csv.writer(f)
                        writer.writerow([timestamp, str(data), label, reason , confidence])

                    # Print alert
                    print(f"\n🚨 Anomaly Detected!\nLabel: {label}\nReason: {reason}\nConfidence Score: {confidence:.4f}\n  ")

            except json.JSONDecodeError:
                print("Error decoding JSON.")
