# import tensorflow as tf
# from tensorflow.keras.models import load_model   # type: ignore
# from tensorflow.keras.preprocessing import image # type: ignore
# import numpy as np
# import efficientnet.tfkeras  # Needed for EfficientNet

# def predict_keras(model_path, image_path, input_size):
#     # Load model
#     model = load_model(model_path, compile=False)

#     # Preprocess image dynamically
#     img = image.load_img(image_path, target_size=(input_size, input_size))
#     img_array = image.img_to_array(img) / 255.0
#     img_array = np.expand_dims(img_array, axis=0)

#     # Predict
#     predictions = model.predict(img_array)
#     return np.argmax(predictions)

import numpy as np
import tensorflow as tf
from tensorflow.keras.models import load_model
from tensorflow.keras.preprocessing import image

# Import EfficientNet FixedDropout
try:
    from efficientnet.model import FixedDropout  # If installed
except ImportError:
    # If EfficientNet is not installed, define a dummy class
    from tensorflow.keras.layers import Dropout
    class FixedDropout(Dropout):
        pass

def predict_keras(model_path, img_path, input_size=224):
    from tensorflow.keras.activations import swish

    # Register all custom objects
    custom_objs = {
        "swish": swish,
        "FixedDropout": FixedDropout
    }

    model = load_model(model_path, custom_objects=custom_objs)

    # Preprocess the image
    img = image.load_img(img_path, target_size=(input_size, input_size))
    img_array = image.img_to_array(img) / 255.0
    img_array = np.expand_dims(img_array, axis=0)

    predictions = model.predict(img_array)

    if predictions.shape[-1] > 1 and not np.allclose(np.sum(predictions, axis=1), 1.0, atol=1e-3):
        predictions = tf.nn.softmax(predictions, axis=1).numpy()

    predicted_index = int(np.argmax(predictions, axis=1)[0])
    confidence = float(np.max(predictions, axis=1)[0])

    return predicted_index, confidence


