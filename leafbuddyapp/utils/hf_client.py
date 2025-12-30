from gradio_client import Client, handle_file

HF_SPACE = "Inoue1/leafbuddy"
API_NAME = "//predict_crop"

client = Client(HF_SPACE)

def predict_with_hf(image_path, crop_name):
    result = client.predict(
        image=handle_file(image_path),
        crop_name=crop_name,
        api_name=API_NAME
    )

    if isinstance(result, dict):
        prediction = result.get("prediction") or result.get("result") or str(result)
        confidence = float(result.get("confidence", 1.0))
    elif isinstance(result, list):
        # if HF returns [dict]
        first = result[0] if len(result) > 0 else {}
        if isinstance(first, dict):
            prediction = first.get("prediction") or str(first)
            confidence = float(first.get("confidence", 1.0))
        else:
            prediction = str(first)
            confidence = 1.0
    else:
        prediction = str(result)
        confidence = 1.0

    return prediction, confidence
