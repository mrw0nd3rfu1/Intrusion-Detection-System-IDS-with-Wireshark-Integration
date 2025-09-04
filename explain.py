# explain.py
import torch
import numpy as np
import matplotlib.pyplot as plt
import lime.lime_tabular
import shap
import os

def explain_model(model, input_data, feature_names=None, class_names=None, save_dir="reports"):
    """
    Explain the model prediction using LIME (primary) and SHAP (fallback).
    Works for CNN, LSTM, Transformer.
    Saves visualizations and text outputs in reports/.
    """
    os.makedirs(save_dir, exist_ok=True)
    device = next(model.parameters()).device
    model.eval()

    if isinstance(input_data, torch.Tensor):
        input_data = input_data.cpu().numpy()

    explainer_lime = lime.lime_tabular.LimeTabularExplainer(
        training_data=input_data,
        feature_names=feature_names if feature_names else [f"f{i}" for i in range(input_data.shape[1])],
        class_names=class_names if class_names else [f"class_{i}" for i in range(len(set(range(2))))],
        mode='classification'
    )

    sample = input_data[0]  # First sample
    predict_fn = lambda x: model(torch.tensor(x, dtype=torch.float32).to(device)).softmax(dim=1).detach().cpu().numpy()

    lime_exp = explainer_lime.explain_instance(
        sample, predict_fn, num_features=min(10, input_data.shape[1])
    )

    lime_exp.save_to_file(os.path.join(save_dir, "lime_explanation.html"))
    with open(os.path.join(save_dir, "lime_explanation.txt"), "w") as f:
        f.write("LIME explanation for first sample:\n")
        f.write(str(lime_exp.as_list()))

    print(f"LIME explanation saved to {save_dir}/lime_explanation.html and .txt")

    # SHAP explanation
    background = torch.tensor(input_data[:50], dtype=torch.float32).to(device)
    test_sample = torch.tensor(input_data[:5], dtype=torch.float32).to(device)

    try:
        explainer = shap.DeepExplainer(model, background)
        shap_values = explainer.shap_values(test_sample, check_additivity=False)
        shap.summary_plot(shap_values, input_data[:5], show=False)
        plt.savefig(os.path.join(save_dir, "shap_summary.png"))
        plt.close()
        print(f"SHAP explanation saved to {save_dir}/shap_summary.png")
    except Exception as e:
        print("SHAP DeepExplainer failed, skipping. Reason:", e)

    print("XAI explanations completed.")
