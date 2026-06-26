import json
import sys
from pathlib import Path

import torch
from transformers import AutoConfig, AutoModelForSequenceClassification, AutoTokenizer


def main() -> int:
    payload = json.loads(sys.stdin.read())
    model_path = Path(payload["model_path"])
    code = payload["code"]

    tokenizer = AutoTokenizer.from_pretrained("microsoft/codebert-base")
    model_config = AutoConfig.from_pretrained("microsoft/codebert-base", num_labels=2)
    model = AutoModelForSequenceClassification.from_config(model_config)
    state_dict = torch.load(
        model_path,
        map_location="cpu",
        weights_only=True,
        mmap=True,
    )
    model.load_state_dict(state_dict)
    model.eval()

    inputs = tokenizer(
        code,
        truncation=True,
        padding="max_length",
        max_length=512,
        return_tensors="pt",
    )

    with torch.no_grad():
        logits = model(**inputs).logits
        probabilities = torch.softmax(logits, dim=1)[0]

    prediction = int(torch.argmax(probabilities).item())
    vulnerable_probability = round(float(probabilities[1].item()), 4)
    print(json.dumps({
        "prediction": prediction,
        "vulnerable_probability": vulnerable_probability,
    }))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
