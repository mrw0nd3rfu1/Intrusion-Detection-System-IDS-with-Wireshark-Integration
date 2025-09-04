# main.py
import argparse
import torch
from torch.utils.data import DataLoader
from models import CNNIDS, LSTMIDS, TransformerIDS
from utils import preprocess_data, IntrusionDataset, hash_packet
from explain import explain_model
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import LabelEncoder
import numpy as np
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, classification_report, confusion_matrix
import joblib
import json

# Model training function
def train_model(model, train_loader, val_loader, criterion, optimizer, device, epochs=20):
    model.to(device)
    for epoch in range(epochs):
        model.train()
        total_loss = 0
        for data, labels in train_loader:
            data, labels = data.to(device), labels.to(device)
            optimizer.zero_grad()
            outputs = model(data)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            total_loss += loss.item()
        print(f"Epoch {epoch+1}, Loss: {total_loss/len(train_loader):.4f}")
    return model

# Model evaluation function, which includes confusion matrix, accuracy, precision recall and f1 score
def evaluate_model(model, loader, device, model_name, save_path="evaluation_results.txt"):
    model.eval()
    y_true, y_pred = [], []
    with torch.no_grad():
        for data, labels in loader:
            data, labels = data.to(device), labels.to(device)
            outputs = model(data)
            _, predicted = torch.max(outputs, 1)
            y_true.extend(labels.cpu().numpy())
            y_pred.extend(predicted.cpu().numpy())

    acc = accuracy_score(y_true, y_pred)
    prec = precision_score(y_true, y_pred, average='weighted', zero_division=0)
    rec = recall_score(y_true, y_pred, average='weighted', zero_division=0)
    f1 = f1_score(y_true, y_pred, average='weighted', zero_division=0)
    report = classification_report(y_true, y_pred)
    cm = confusion_matrix(y_true, y_pred)

    # Print to console
    print(report)
    print("Confusion Matrix:\n", cm)

    # Save to file
    with open(save_path, "a") as f:
        f.write(f"Model: {model_name}\n")
        f.write(f"Accuracy: {acc:.4f}\nPrecision: {prec:.4f}\nRecall: {rec:.4f}\nF1-Score: {f1:.4f}\n")
        f.write("Classification Report:\n")
        f.write(report + "\n")
        f.write("Confusion Matrix:\n")
        f.write(str(cm) + "\n")
        f.write("="*50 + "\n")

# Main function which runs and calls all the classes
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--data", type=str, required=True, help="Path to dataset CSV")
    parser.add_argument("--model", type=str, choices=["CNN", "LSTM", "Transformer"], default="CNN")
    parser.add_argument("--epochs", type=int, default=10)
    args = parser.parse_args()

    # Encoding and preprocessing the data
    df = preprocess_data(args.data)

    label_encoder = LabelEncoder()
    df['label'] = label_encoder.fit_transform(df['label'])

    # Save label encoder for UI
    joblib.dump(label_encoder, f"label_encoder_{args.model}.pkl")
    print(f"✅ LabelEncoder saved as label_encoder_{args.model}.pkl")

    # Training and Validation split
    train_df, val_df = train_test_split(df, test_size=0.2, stratify=df['label'])
    train_set = IntrusionDataset(train_df)
    val_set = IntrusionDataset(val_df)
    train_loader = DataLoader(train_set, batch_size=64, shuffle=True)
    val_loader = DataLoader(val_set, batch_size=64, shuffle=False)

    input_dim = train_set[0][0].shape[0]
    num_classes = len(np.unique(train_set.y))

    # Selection of model to train
    if args.model == "CNN":
        model = CNNIDS(input_dim, num_classes)
    elif args.model == "LSTM":
        model = LSTMIDS(input_dim, 64, num_classes)
    elif args.model == "Transformer":
        model = TransformerIDS(input_dim, num_classes)

    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    device = torch.device("cuda" if torch.cuda.is_available() else "cpu")

    # Training the model
    model = train_model(model, train_loader, val_loader, criterion, optimizer, device, args.epochs)

    # Evaluating the model
    evaluate_model(model, val_loader, device, args.model)

    # XAI for the model
    explain_model(model, df.drop("label", axis=1).values[:100])

    # Saving the model for UI use
    torch.save({
        'model_state_dict': model.state_dict(),
        'num_classes': num_classes,
        'input_dim': input_dim
    }, f"saved_model_{args.model}.pt")
    print(f"✅ Model saved as saved_model_{args.model}.pt with metadata")

    # Random SHA to print
    test_packet = "SRC:192.168.0.1 DST:192.168.0.2 DATA:Test"
    print("SHA-256 Hash:", hash_packet(test_packet))


if __name__ == "__main__":
    main()
