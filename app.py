from fastapi import FastAPI
from pydantic import BaseModel, Field
import pandas as pd
import joblib
from fastapi.middleware.cors import CORSMiddleware


app = FastAPI()

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow all origins
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
) 

# Define the input schema with aliases for special characters
class InputData(BaseModel):
    tcp_srcport: int = Field(..., alias="tcp.srcport")
    tcp_dstport: int = Field(..., alias="tcp.dstport")
    ip_proto: int = Field(..., alias="ip.proto")
    frame_len: int = Field(..., alias="frame.len")
    tcp_flags_syn: int = Field(..., alias="tcp.flags.syn")
    tcp_flags_reset: int = Field(..., alias="tcp.flags.reset")
    tcp_flags_push: int = Field(..., alias="tcp.flags.push")
    tcp_flags_ack: int = Field(..., alias="tcp.flags.ack")
    ip_flags_mf: int = Field(..., alias="ip.flags.mf")
    ip_flags_df: int = Field(..., alias="ip.flags.df")
    ip_flags_rb: int = Field(..., alias="ip.flags.rb")
    tcp_seq: int = Field(..., alias="tcp.seq")
    tcp_ack: int = Field(..., alias="tcp.ack")
    packets: int = Field(..., alias="Packets")
    bytes: int = Field(..., alias="Bytes")
    tx_packets: int = Field(..., alias="Tx Packets")
    tx_bytes: int = Field(..., alias="Tx Bytes")
    rx_packets: int = Field(..., alias="Rx Packets")
    rx_bytes: int = Field(..., alias="Rx Bytes")

    class Config:
        populate_by_name = True

# Load your trained model once during startup
model = joblib.load('models/model.pkl')

# Define your class label mapping
class_label_mapping = {
    0: "Benign",
    1: "DDoS-ACK",
    2: "DDoS-PSH-ACK"
}

@app.get("/")
async def read_root():
    return {"health_check": "OK", "model_version": 1}

@app.post("/predict")
async def predict(input_data: InputData):
    # Convert input data to a DataFrame
    data_dict = input_data.model_dump(by_alias=True)
    df = pd.DataFrame([data_dict])

    # Make a prediction
    predicted_class = int(model.predict(df)[0])
    class_label = class_label_mapping.get(predicted_class, "Unknown")

    return {
        "predicted_class": predicted_class,
        "class_label": class_label
    }


# Example Input for Testing:
example_input = {
    "tcp.srcport": 52332,
    "tcp.dstport": 8000,
    "ip.proto": 6,
    "frame.len": 66,
    "tcp.flags.syn": 0,
    "tcp.flags.reset": 0,
    "tcp.flags.push": 0,
    "tcp.flags.ack": 1,
    "ip.flags.mf": 0,
    "ip.flags.df": 1,
    "ip.flags.rb": 0,
    "tcp.seq": 1,
    "tcp.ack": 1,
    "Packets": 10,
    "Bytes": 1144,
    "Tx Packets": 6,
    "Tx Bytes": 560,
    "Rx Packets": 4,
    "Rx Bytes": 584
}
