from supabase import create_client
from decouple import config
import os

SUPABASE_URL = config('SUPABASE_URL')
SUPABASE_SERVICE_ROLE_KEY = config('SUPABASE_SERVICE_ROLE_KEY')

supabase = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)

crops = [
    {
        "name": "banana",
        "model_type": "keras",
        "model_file": "banana_model.keras",
        "label_file": "banana_labels.json",
        "input_size": 224
    },
    {
        "name": "beans",
        "model_type": "keras",
        "model_file": "beans_model.keras",
        "label_file": "beans_labels.json",
        "input_size": 224
    },
    {
        "name": "chili",
        "model_type": "keras",
        "model_file": "chili_model.keras",
        "label_file": "chili_labels.json",
        "input_size": 224
    },
    {
        "name": "corn",
        "model_type": "keras",
        "model_file": "corn_model.keras",
        "label_file": "corn_labels.json",
        "input_size": 300
    },
    {
        "name": "eggplant",
        "model_type": "pytorch",
        "model_file": "eggplant_model.pth",
        "label_file": "eggplant_labels.json",
        "input_size": 224
    },
    {
        "name": "rice",
        "model_type": "keras",
        "model_file": "rice_model.keras",
        "label_file": "rice_labels.json",
        "input_size": 224
    },
]

for crop in crops:
    # res = supabase.table("leafbuddyapp_crop")\
    #     .update({"input_size": crop["input_size"]})\
    #     .eq("name", crop["name"])\
    #     .execute()
    # print(res)

    res = supabase.table("leafbuddyapp_crop").upsert(crops).execute()
    print(res)


