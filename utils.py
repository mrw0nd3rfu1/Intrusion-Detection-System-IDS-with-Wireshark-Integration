# utils.py
import pandas as pd
import numpy as np
from sklearn.preprocessing import LabelEncoder, MinMaxScaler
from torch.utils.data import Dataset
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend

import torch
import pandas as pd
from sklearn.preprocessing import LabelEncoder

label_encoder = LabelEncoder()

# Preprocessing the data
def preprocess_data(data):
    # data: file path or DataFrame
    if isinstance(data, str):
        df = pd.read_csv(data)
    elif isinstance(data, pd.DataFrame):
        df = data.copy()
    else:
        raise ValueError("preprocess_data expects path or pandas DataFrame")

    df = df.copy()
    df.dropna(inplace=True)

    # encoding the label
    label_col = 'label' if 'label' in df.columns else None

    # Encode object columns (excluding label)
    for col in df.select_dtypes(include=['object']).columns:
        if col == label_col:
            continue
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))

    # Scale numeric features
    feature_cols = df.columns.difference([label_col]) if label_col else df.columns
    scaler = MinMaxScaler()
    df[feature_cols] = scaler.fit_transform(df[feature_cols].astype(float))

    # final sanity checks
    numeric = df.select_dtypes(include=[np.number])
    if numeric.isnull().values.any() or not np.isfinite(numeric.values).all():
        raise ValueError("preprocessing produced NaN or Inf values")

    return df

# Creating the dataloader for model to train
class IntrusionDataset(torch.utils.data.Dataset):
    def __init__(self, df):
        if "label" in df.columns:
            self.X = df.drop("label", axis=1).values.astype(np.float32)
            self.y = df["label"].values
        else:
            self.X = df.values.astype(np.float32)
            self.y = None

    def __len__(self):
        return len(self.X)

    def __getitem__(self, idx):
        if self.y is not None:
            return torch.tensor(self.X[idx]), torch.tensor(self.y[idx])
        else:
            return torch.tensor(self.X[idx])


# Converting to hash packets
def hash_packet(packet: str) -> str:
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(packet.encode('utf-8'))
    return digest.finalize().hex()
