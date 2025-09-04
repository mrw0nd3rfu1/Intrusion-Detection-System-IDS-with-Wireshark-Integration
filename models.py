# models.py
import torch
import torch.nn as nn
import torch.nn.functional as F

# CNN model architecture
class CNNIDS(nn.Module):
    def __init__(self, input_dim, num_classes):
        super(CNNIDS, self).__init__()
        self.conv1 = nn.Conv1d(1, 32, kernel_size=3)
        self.pool = nn.MaxPool1d(2)
        self.fc1 = nn.Linear((input_dim - 2) // 2 * 32, 128)
        self.fc2 = nn.Linear(128, num_classes)

    def forward(self, x):
        x = x.unsqueeze(1)
        x = self.pool(F.relu(self.conv1(x)))
        x = x.view(x.size(0), -1)
        x = F.relu(self.fc1(x))
        return self.fc2(x)

# LSTM model architecture
class LSTMIDS(nn.Module):
    def __init__(self, input_dim, hidden_dim, num_classes):
        super(LSTMIDS, self).__init__()
        self.lstm = nn.LSTM(input_dim, hidden_dim, batch_first=True)
        self.fc = nn.Linear(hidden_dim, num_classes)

    def forward(self, x):
        x = x.unsqueeze(1)  # batch_size x 1 x features
        _, (hn, _) = self.lstm(x)
        return self.fc(hn[-1])

# Transformer model architecture
class TransformerIDS(nn.Module):
    def __init__(self, input_dim, num_classes, nhead=4, num_layers=2):
        super(TransformerIDS, self).__init__()
        self.embedding = nn.Linear(input_dim, 64)
        encoder_layer = nn.TransformerEncoderLayer(d_model=64, nhead=nhead)
        self.transformer = nn.TransformerEncoder(encoder_layer, num_layers=num_layers)
        self.fc = nn.Linear(64, num_classes)

    def forward(self, x):
        x = self.embedding(x).unsqueeze(1)
        x = self.transformer(x)
        return self.fc(x.mean(dim=1))
