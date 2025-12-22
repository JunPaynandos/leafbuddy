from django.shortcuts import render, redirect
from django.core.files.storage import default_storage
from .inference.pytorch_infer import predict_pytorch
from .inference.keras_infer import predict_keras
import os, json, uuid, bcrypt, requests
from .models import AnalysisHistory
from django.contrib import messages
from supabase import create_client
from django.conf import settings
from django.urls import reverse

from django.contrib.auth.tokens import default_token_generator
from django.core.mail import send_mail
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.template.loader import render_to_string
from django.contrib.auth.models import User
from django.contrib.sites.shortcuts import get_current_site
from django.utils.encoding import force_bytes
from django.contrib.auth.forms import UserCreationForm
from .utils.supabase_user import SupabaseUser
from .password_reset_utils import generate_password_reset_token, verify_password_reset_token

from django.core.mail import EmailMultiAlternatives
from datetime import datetime, timezone, timedelta
from dateutil import parser
from postgrest.exceptions import APIError
import secrets
from django.utils.html import strip_tags


# from .supabase import supabase

SUPABASE_URL = settings.SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY = settings.SUPABASE_SERVICE_ROLE_KEY

supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

DISEASE_JSON_PATH = os.path.join(settings.BASE_DIR, "data", "disease_info.json")
with open(DISEASE_JSON_PATH, "r") as f:
    DISEASE_DATA = json.load(f)

# Map crop type to model path
MODEL_PATHS = {
    'banana': 'models/banana_model.keras',
    'beans': 'models/beans_model.keras',
    'chili': 'models/chili_model.keras',
    'corn': 'models/corn_model.keras',
    'eggplant': 'models/eggplant_model.pth',
    'rice': 'models/rice_model.keras',
}

def home(request):
    return render(request, 'user/index.html', {'current_page': 'home'})


import os
import uuid
import json
from mimetypes import guess_type
from django.conf import settings
from django.core.files.storage import default_storage
from django.shortcuts import render, redirect
from .models import AnalysisHistory

from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
import tempfile
import base64

def scan(request):
    # Get crops list from Supabase
    crops_res = supabase.table("leafbuddyapp_crop").select("*").execute()
    crops = crops_res.data

    if request.method == "POST":
        crop_id = request.POST.get("crop_type")
        leaf_image = request.FILES.get("leaf_image")

        # Validate crop
        crop = next((c for c in crops if str(c["id"]) == crop_id), None)
        if not crop:
            return render(request, "user/scan.html", {"crops": crops, "error": "Invalid crop selected."})

        # Model & input size
        model_path = os.path.join(settings.BASE_DIR, "models", crop["model_file"])
        input_size = crop.get("input_size", 224)

        # Save uploaded file temporarily
        temp_path = default_storage.save(f"uploads/{leaf_image.name}", leaf_image)
        temp_full_path = os.path.join(settings.MEDIA_ROOT, temp_path)

        # Prepare filename and user folder
        unique_filename = f"{uuid.uuid4()}_{leaf_image.name}"
        user_id = request.user.id if request.user.is_authenticated else "guest"
        file_key = f"users/{user_id}/{unique_filename}"

        # Default fallback to local /media/ URL
        image_url = f"{settings.MEDIA_URL}{temp_path}"

        # Try Supabase upload
        try:
            content_type = guess_type(temp_full_path)[0] or "application/octet-stream"
            with open(temp_full_path, "rb") as file_obj:
                file_data = file_obj.read()

            upload_response = supabase.storage.from_("leaf-images").upload(
                file_key,
                file_data,
                {"content-type": content_type}
            )

            if upload_response.get("error"):
                print("🚨 Supabase upload error:", upload_response["error"])
            else:
                print("✅ Supabase upload success:", upload_response)
                image_url = supabase.storage.from_("leaf-images").get_public_url(file_key)

        except Exception as e:
            import traceback
            print("🚨 Exception during Supabase upload:", e)
            traceback.print_exc()

        # Load class labels
        label_path = os.path.join(settings.BASE_DIR, "labels", crop["label_file"])
        with open(label_path, "r") as f:
            class_labels = json.load(f)

        # Prediction
        try:
            if model_path.endswith(".keras"):
                prediction_index, confidence = predict_keras(model_path, temp_full_path, input_size)
            elif model_path.endswith(".pth"):
                num_classes = len(class_labels)
                prediction_index, confidence = predict_pytorch(
                    model_path, temp_full_path, num_classes, input_size=(input_size, input_size)
                )
            else:
                raise ValueError("Unsupported model format.")
        except Exception as e:
            import traceback
            print("🚨 Prediction error:", e)
            traceback.print_exc()
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": f"Prediction error: {e}"
            })

        predicted_class = class_labels[prediction_index]
        crop_key = crop["name"].lower()
        disease_key = predicted_class.lower()

        disease_info = DISEASE_DATA.get(crop_key, {}).get(disease_key, {})

        # Save history if logged in
        # if request.user.is_authenticated:
        #     AnalysisHistory.objects.create(
        #         user=request.user,
        #         crop_id=crop["id"],
        #         image_url=image_url,
        #         predicted_class=predicted_class,
        #         description=disease_info.get("description", "No description available."),
        #         symptoms=disease_info.get("symptoms", "No symptoms available."),
        #         treatment=disease_info.get("treatment", "No treatment available."),
        #         prevention=disease_info.get("prevention", "No prevention available."),
        #     )

        # Save history if logged in using Supabase session user
        if "user_id" in request.session:
            AnalysisHistory.objects.create(
                user_id=request.session["user_id"],  # Use Supabase ID
                crop_id=crop["id"],
                image_url=image_url,
                predicted_class=predicted_class,
                confidence=round(confidence * 100, 2),
                description=disease_info.get("description", "No description available."),
                symptoms=disease_info.get("symptoms", "No symptoms available."),
                treatment=disease_info.get("treatment", "No treatment available."),
                prevention=disease_info.get("prevention", "No prevention available."),
        )

        # Store in session for result page
        request.session["scan_result"] = {
            "result": predicted_class,
            "confidence": round(confidence * 100, 2),
            "crop": crop["name"].capitalize(),
            "image_url": image_url,
            "description": disease_info.get("description", "No description available."),
            "symptoms": disease_info.get("symptoms", "No symptoms available."),
            "treatment": disease_info.get("treatment", "No treatment available."),
            "prevention": disease_info.get("prevention", "No prevention available."),
        }

        return redirect("result")

    return render(request, "user/scan.html", {"crops": crops, "current_page": "features"})

def result(request):
    data = request.session.pop("scan_result", None)
    if not data:
        return redirect("scan")

    return render(request, "user/result.html", {**data, "current_page": "features"})

@csrf_exempt
def predict_frame(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    crop_id = request.POST.get("crop_type")
    image_file = request.FILES.get("frame")

    if not crop_id or not image_file:
        return JsonResponse({"error": "Missing crop_type or frame"}, status=400)

    # Get crop info
    crops_res = supabase.table("leafbuddyapp_crop").select("*").execute()
    crops = crops_res.data
    crop = next((c for c in crops if str(c["id"]) == crop_id), None)

    if not crop:
        return JsonResponse({"error": "Invalid crop_type"}, status=400)

    # Save frame to a temp file
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp_file:
        for chunk in image_file.chunks():
            tmp_file.write(chunk)
        temp_path = tmp_file.name

    # Predict
    try:
        model_path = os.path.join(settings.BASE_DIR, "models", crop["model_file"])
        input_size = crop.get("input_size", 224)
        label_path = os.path.join(settings.BASE_DIR, "labels", crop["label_file"])

        with open(label_path, "r") as f:
            class_labels = json.load(f)

        if model_path.endswith(".keras"):
            prediction_index, confidence = predict_keras(model_path, temp_path, input_size)
        elif model_path.endswith(".pth"):
            num_classes = len(class_labels)
            prediction_index, confidence = predict_pytorch(
                model_path, temp_path, num_classes, input_size=(input_size, input_size)
            )
        else:
            raise ValueError("Unsupported model format")

        predicted_class = class_labels[prediction_index]

        return JsonResponse({
            "disease": predicted_class,
            "confidence": round(confidence * 100, 2),
        })

    except Exception as e:
        return JsonResponse({"error": str(e)}, status=500)

from django.contrib.auth.decorators import login_required
from uuid import UUID

def analysis_history(request):
    if "user_id" not in request.session:
        return redirect("login")

    user_id = request.session["user_id"]

    analysis_history = AnalysisHistory.objects.filter(user_id=user_id).order_by("-created_at")

    return render(request, "user/history.html", {"analysis_history": analysis_history})

def delete_history(request, id):
    if "user_id" not in request.session:
        return redirect("login")

    user_id = request.session["user_id"]

    if request.method == "POST":
        history = get_object_or_404(AnalysisHistory, id=id, user_id=user_id)
        history.delete()
        
    return redirect('history')

def load_disease_data():
    json_path = os.path.join(settings.BASE_DIR, "data", "disease_info.json")
    with open(json_path, "r") as f:
        return json.load(f)

def load_disease_images():
    # Load the disease_images.json file located in your static folder
    json_file_path = os.path.join(settings.BASE_DIR, "data", "disease_images.json")
    
    try:
        with open(json_file_path, 'r') as file:
            return json.load(file)  # Returns a dictionary of disease names and related image URLs
    except Exception as e:
        return {}

def library(request):
    data = load_disease_data()
    
    crops = []
    for crop_name, crop_data in data.items():
        crops.append({
            "name": crop_name.capitalize(),
            "image": crop_data.get("thumbnail_image"),
            "scientific_name": crop_data.get("scientific_name"),
        })

    return render(request, "user/library.html", {"crops": crops, "current_page": "features"})

def crop_diseases(request, crop_name):
    data = load_disease_data()
    crop = data.get(crop_name.lower())
    if not crop:
        return redirect("library")

    diseases = []
    for disease_name, disease_data in crop.items():
        if disease_name not in ['scientific_name', 'thumbnail_image']:
            disease_image = disease_data.get('image')  # Assuming disease-specific image key is `image`
            diseases.append({
                "name": disease_name.capitalize(),
                "image": disease_image,
            })

    return render(request, "user/disease_list.html", {"crop_name": crop_name.capitalize(), "diseases": diseases, "current_page": "features"})

def disease_detail(request, crop_name, disease_name):
    data = load_disease_data()
    crop = data.get(crop_name.lower(), {})
    disease = crop.get(disease_name.lower())
    
    if not disease:
        return redirect("crop_diseases", crop_name=crop_name)

    # is_healthy = "healthy" in disease_name.lower()
    is_healthy = "healthy" in disease_name.lower() or disease_name.lower() == "undefined"

    # Fetch the disease image directly from the disease data
    disease_image = disease.get('image')  # This should be the path of the disease image

    disease_images = load_disease_images()
    related_images = disease_images.get(disease_name.lower(), [])

    context = {
        "crop_name": crop_name.capitalize(),
        "disease_name": disease_name.capitalize(),
        "is_healthy": is_healthy,
        "image_path": disease_image,  # Pass the disease-specific image path
        "related_images": json.dumps(related_images),
        "current_page": "features"
    }

    if is_healthy:
        context["description"] = disease.get("description", "")
    else:
        context.update(disease)

    return render(request, "user/disease_details.html", context)

def about(request):
    return render(request, 'user/about.html', {'current_page': 'about'})

def contact(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        message = request.POST.get('message')
        messages.success(request, "Message sent successfully!")
        return redirect('contact')
    return render(request, 'user/contact.html', {'current_page': 'contact'})

def signup(request):
    google_auth_url = (
        f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to="
        f"{request.build_absolute_uri(reverse('auth_callback'))}"
    )

    if request.method == "POST":
        first_name = request.POST["first_name"].strip()
        last_name = request.POST["last_name"].strip()
        username = request.POST["username"].strip()
        email = request.POST["email"].strip()
        password = request.POST["password"]

        errors = {}

        if not first_name:
            errors["first_name"] = "First name is required."
        if not last_name:
            errors["last_name"] = "Last name is required."
        if not username:
            errors["username"] = "Username is required."
        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."

        # Check email uniqueness
        if not errors:
            existing_email = supabase.table("users").select("email").eq("email", email).execute()
            if existing_email.data:
                errors["email"] = "Email already registered."

            # Check username uniqueness
            existing_username = supabase.table("users").select("username").eq("username", username).execute()
            if existing_username.data:
                errors["username"] = "Username already taken."

        if errors:
            return render(request, "auth/signup.html", {
                "google_auth_url": google_auth_url,
                "errors": errors,
                "form_data": {
                    "first_name": first_name,
                    "last_name": last_name,
                    "username": username,
                    "email": email,
                },
            })

        hashed_pw = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt()).decode("utf-8")

        response = supabase.table("users").insert([{
            "first_name": first_name,
            "last_name": last_name,
            "username": username,
            "email": email,
            "password": hashed_pw,
            "profile_image": None,
            "is_active": False
        }]).execute()

        new_user = response.data[0]

        initials = (first_name[:1] + last_name[:1]).upper()

        request.session["user_email"] = email
        request.session["user_name"] = f"{first_name} {last_name}"
        request.session["profile_image"] = None
        request.session["initials"] = initials

        lb_user = SupabaseUser(new_user)

        send_confirmation_email(lb_user, request)

        return render(request, "auth/email_verification.html", {
            "user_email": email
        })

    return render(request, "auth/signup.html", {"google_auth_url": google_auth_url})

def send_confirmation_email(user, request):
    token = default_token_generator.make_token(user)
    uid = urlsafe_base64_encode(force_bytes(user.pk))
    domain = "127.0.0.1:8000" if settings.DEBUG else get_current_site(request).domain
    activation_url = f"http://{domain}/auth/confirm-email/{uid}/{token}/"

    subject = "Confirm Your Email Address"
    from_email = "LeafBuddy <leafbuddy8gmail.com>"
    to_email = user.email

    html_content = render_to_string("auth/confirmation_email.html", {
        "activation_url": activation_url
    })
    text_content = f"Please click the following link to confirm your email: {activation_url}"

    msg = EmailMultiAlternatives(subject, text_content, from_email, [to_email])
    msg.attach_alternative(html_content, "text/html")
    msg.send()

def confirm_email(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user_dict = supabase.table("users").select("*").eq("id", uid).execute().data[0]
        mock_user = SupabaseUser(user_dict)  # Wrap here

        if default_token_generator.check_token(mock_user, token):
            supabase.table("users").update({
                "is_active": True,
                "email_verified": True
            }).eq("id", uid).execute()

            messages.success(request, "Your email has been confirmed. You can now log in.")
            return redirect("login")
        else:
            messages.error(request, "The confirmation link is invalid or has expired.")
            return redirect("signup")

    except Exception as e:
        messages.error(request, "Something went wrong. Please try again.")
        return redirect("signup")

def resend_confirmation_email(request):
    email = request.GET.get("email")

    if not email:
        messages.error(request, "Missing email.")
        return redirect("login")

    # Fetch user from Supabase
    user_res = supabase.table("users").select("*").eq("email", email).single().execute()

    if not user_res.data:
        messages.error(request, "User not found.")
        return redirect("login")

    user = user_res.data

    # Throttle resends
    last_sent = user.get("last_confirmation_email_sent")
    now = datetime.utcnow()

    if last_sent:
        last_sent_dt = parser.isoparse(last_sent)
        if now - last_sent_dt < timedelta(minutes=2):
            messages.warning(request, "You can only resend the email every 2 minutes.")
            return redirect("confirm_email")

    # Token and expiry
    token = default_token_generator.make_token(SupabaseUser(user))
    uid = urlsafe_base64_encode(force_bytes(user["id"]))

    domain = "127.0.0.1:8000" if settings.DEBUG else get_current_site(request).domain
    confirm_url = f"http://{domain}{reverse('confirm_email', args=[uid, token])}"

    # Save metadata to Supabase
    supabase.table("users").update({
        "email_verification_token": token,
        "email_verification_token_expiry": (now + timedelta(hours=1)).isoformat(),
        "last_confirmation_email_sent": now.isoformat()
    }).eq("id", user["id"]).execute()

    # Email content
    subject = "Confirm your email - LeafBuddy"
    text_message = f"Click the link to confirm your email: {confirm_url}"
    html_message = render_to_string("auth/confirmation_email.html", {
        "confirm_url": confirm_url
    })

    send_mail(
        subject,
        text_message,
        settings.DEFAULT_FROM_EMAIL,
        [email],
        html_message=html_message,
        fail_silently=False,
    )

    messages.success(request, "A new confirmation email has been sent.")
    return redirect("confirm_email")

def login(request):
    google_auth_url = (
        f"{SUPABASE_URL}/auth/v1/authorize?provider=google&redirect_to="
        f"{request.build_absolute_uri(reverse('auth_callback'))}"
    )

    form_data = {"email": ""}
    errors = {}

    if request.method == "POST":
        email = request.POST["email"].strip()
        password = request.POST["password"]
        form_data["email"] = email


        if not email:
            errors["email"] = "Email is required."
        if not password:
            errors["password"] = "Password is required."

        user_data = None
        if not errors:
            user = supabase.table("users").select("*").eq("email", email).execute()
            if not user.data:
                errors["email"] = "Invalid email or password."
            else:
                user_data = user.data[0]
                if not bcrypt.checkpw(password.encode(), user_data["password"].encode()):
                    errors["email"] = "Invalid email or password."

        if errors:
            return render(request, "auth/login.html", {
                "google_auth_url": google_auth_url,
                "errors": errors,
                "form_data": form_data,
            })

        # Update last_login
        supabase.table("users").update({
            "last_login": datetime.now(timezone.utc).isoformat()
        }).eq("id", user_data["id"]).execute()

        initials = (user_data["first_name"][:1] + user_data["last_name"][:1]).upper()

        request.session["user_id"] = user_data["id"]
        request.session["user_email"] = user_data["email"]
        request.session["user_name"] = f"{user_data['first_name']} {user_data['last_name']}"
        request.session["profile_image"] = user_data.get("profile_image")
        request.session["initials"] = initials

        return redirect("home")

    return render(request, "auth/login.html", {"google_auth_url": google_auth_url, "form_data": form_data,
        "errors": errors})

def set_password_view(request):
    if 'user_email' not in request.session:
        return redirect('login')

    if request.method == 'POST':
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return render(request, 'auth/set_password.html')

        hashed_pw = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

        # Update password in Supabase
        supabase.table("users").update({"password": hashed_pw}).eq("email", request.session['user_email']).execute()

        messages.success(request, "Password set successfully! You can now use email/password to sign in.")
        return redirect('home')

    return render(request, 'auth/set_password.html')

def logout(request):
    # revoke session in Supabase
    access_token = request.session.get("access_token")
    if access_token:
        requests.post(
            f"{SUPABASE_URL}/auth/v1/logout",
            headers={"Authorization": f"Bearer {access_token}"}
        )

    request.session.flush()

    return redirect("home")

# def auth_callback(request):
#     access_token = request.GET.get("access_token")
#     if not access_token:
#         return redirect("login")

#     # Get user info from Supabase
#     headers = {"Authorization": f"Bearer {access_token}", "apikey": SUPABASE_SERVICE_ROLE_KEY}
#     res = requests.get(f"{SUPABASE_URL}/auth/v1/user", headers=headers)

#     if res.status_code != 200:
#         return redirect("login")

#     user_data = res.json()
#     email = user_data.get("email")
#     metadata = user_data.get("user_metadata", {})
#     first_name = metadata.get("full_name", "").split(" ")[0] or "User"
#     last_name = " ".join(metadata.get("full_name", "").split(" ")[1:]) or ""
#     avatar_url = metadata.get("avatar_url")

#     existing = supabase.table("users").select("*").eq("email", email).execute()

#     if existing.data:
#         user = existing.data[0]

#         # If user has no auth_provider or it's still 'email', update it to google
#         if user.get("auth_provider") != "google":
#             supabase.table("users").update({
#                 "auth_provider": "google",
#                 "profile_image": avatar_url or user.get("profile_image"),
#                 "first_name": user.get("first_name") or first_name,
#                 "last_name": user.get("last_name") or last_name
#             }).eq("id", user["id"]).execute()

#         supabase.table("users").update({
#             "last_login": datetime.now(timezone.utc).isoformat()
#         }).eq("id", user["id"]).execute()

#         user = supabase.table("users").select("*").eq("id", user["id"]).single().execute().data

#     else:
#         insert = supabase.table("users").insert([{
#             "first_name": first_name,
#             "last_name": last_name,
#             "username": email.split("@")[0],
#             "email": email,
#             "password": None,
#             "profile_image": avatar_url,
#             "auth_provider": "google",
#             "last_login": datetime.now(timezone.utc).isoformat()
#         }]).execute()

#         user = insert.data[0]

#         print("PROFILE IMAGE SESSION:", user.get("profile_image"))

#     initials = (user.get("first_name", "")[:1] + user.get("last_name", "")[:1]).upper()

#     request.session["user_id"] = user_data["id"]
#     request.session["user_email"] = user["email"]
#     request.session["user_name"] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
#     request.session["profile_image"] = user.get("profile_image")
#     request.session["initials"] = initials

#     if user.get("password") is None:
#         messages.info(request, "You signed in with Google. Set a password to enable email login.")
#         return redirect("set_password")

#     return redirect("home")

def auth_callback(request):
    access_token = request.GET.get("access_token")
    if not access_token:
        return redirect("login")

    # Get user info from Supabase
    headers = {"Authorization": f"Bearer {access_token}", "apikey": SUPABASE_SERVICE_ROLE_KEY}
    res = requests.get(f"{SUPABASE_URL}/auth/v1/user", headers=headers)

    if res.status_code != 200:
        return redirect("login")

    user_data = res.json()
    email = user_data.get("email")
    metadata = user_data.get("user_metadata", {})
    first_name = metadata.get("full_name", "").split(" ")[0] or "User"
    last_name = " ".join(metadata.get("full_name", "").split(" ")[1:]) or ""
    avatar_url = metadata.get("avatar_url")

    # Query by email (not UUID)
    existing = supabase.table("users").select("*").eq("email", email).execute()

    if existing.data:
        user = existing.data[0]

        # If user has no auth_provider or it's still 'email', update it to google
        if user.get("auth_provider") != "google":
            supabase.table("users").update({
                "auth_provider": "google",
                "profile_image": avatar_url or user.get("profile_image"),
                "first_name": user.get("first_name") or first_name,
                "last_name": user.get("last_name") or last_name
            }).eq("id", user["id"]).execute()

        supabase.table("users").update({
            "last_login": datetime.now(timezone.utc).isoformat()
        }).eq("id", user["id"]).execute()

        user = supabase.table("users").select("*").eq("id", user["id"]).single().execute().data

    else:
        insert = supabase.table("users").insert([{
            "first_name": first_name,
            "last_name": last_name,
            "username": email.split("@")[0],
            "email": email,
            "password": None,
            "profile_image": avatar_url,
            "auth_provider": "google",
            "last_login": datetime.now(timezone.utc).isoformat()
        }]).execute()

        user = insert.data[0]

    initials = (user.get("first_name", "")[:1] + user.get("last_name", "")[:1]).upper()

    request.session["user_id"] = user["id"]  # Store the `bigint` ID
    request.session["user_email"] = user["email"]
    request.session["user_name"] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
    request.session["profile_image"] = user.get("profile_image")
    request.session["initials"] = initials

    if user.get("password") is None:
        messages.info(request, "You signed in with Google. Set a password to enable email login.")
        return redirect("set_password")

    return redirect("home")


# def settings_view(request):
#     if not request.session.get("user_email"):
#         return redirect("login")

#     user_id = request.session["user_id"]

#     # Fetch user from Supabase
#     user_res = supabase.table("users").select("*").eq("id", user_id).single().execute()

#     if not user_res.data:
#         messages.error(request, "User not found.")
#         return redirect("login")

#     user = user_res.data

#     full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
#     email = user.get("email")
#     profile_image = user.get("profile_image")
#     initials = (user.get("first_name", "")[:1] + user.get("last_name", "")[:1]).upper()

#     context = {
#         "full_name": full_name,
#         "email": email,
#         "profile_image": profile_image,
#         "initials": initials,
#         "current_page": "settings",
#     }

#     return render(request, "user/user_settings.html", context)

# def settings_view(request):
#     if not request.session.get("user_email"):
#         return redirect("login")

#     # Get user_id from session
#     user_id = request.session["user_id"]

#     # Ensure that user_id is UUID type (if not, you might need to cast it)
#     try:
#         # Convert user_id to UUID if it isn't already
#         user_id = uuid.UUID(user_id)
#     except ValueError:
#         messages.error(request, "Invalid user ID format.")
#         return redirect("login")

#     # Fetch user from Supabase (make sure 'id' column is UUID type)
#     user_res = supabase.table("users").select("*").eq("id", str(user_id)).single().execute()

#     if not user_res.data:
#         messages.error(request, "User not found.")
#         return redirect("login")

#     user = user_res.data

#     # Construct full name and other details
#     full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
#     email = user.get("email")
#     profile_image = user.get("profile_image")
#     initials = (user.get("first_name", "")[:1] + user.get("last_name", "")[:1]).upper()

#     context = {
#         "full_name": full_name,
#         "email": email,
#         "profile_image": profile_image,
#         "initials": initials,
#         "current_page": "settings",
#     }

#     return render(request, "user/user_settings.html", context)

# def settings_view(request):
#     if not request.session.get("user_email"):
#         return redirect("login")

#     # Get user_id from session
#     user_id = request.session["user_id"]

#     # Ensure that user_id is UUID type (if not, you might need to cast it)
#     try:
#         # Convert user_id to UUID if it isn't already
#         user_id = uuid.UUID(user_id)
#     except ValueError:
#         messages.error(request, "Invalid user ID format.")
#         return redirect("login")

#     # Fetch user from Supabase (make sure 'id' column is UUID type)
#     user_res = supabase.table("users").select("*").eq("id", str(user_id)).single().execute()

#     if not user_res.data:
#         messages.error(request, "User not found.")
#         return redirect("login")

#     user = user_res.data

#     # Handle full name split correctly: 
#     # 'first_name' is 'Allan Caye' and 'last_name' is 'Megumin'
#     full_name = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()

#     # Split 'first_name' into parts. The entire first_name is 'Allan Caye' in your case
#     first_name = user.get('first_name', '')
    
#     # The 'last_name' remains as is
#     last_name = user.get('last_name', '')

#     # Construct initials (first letter of first_name and last_name)
#     initials = (first_name[:1] + last_name[:1]).upper()

#     email = user.get("email")
#     profile_image = user.get("profile_image")

#     context = {
#         "full_name": full_name,
#         "first_name": first_name,
#         "last_name": last_name,
#         "email": email,
#         "profile_image": profile_image,
#         "initials": initials,
#         "current_page": "settings",
#     }

#     return render(request, "user/user_settings.html", context)


from django.shortcuts import render, redirect
from django.contrib import messages
from django.core.exceptions import ValidationError
from django.core.files.storage import FileSystemStorage
from django.contrib.auth import get_user_model  # Get custom user model
from uuid import UUID

User = get_user_model()  # This will use your custom user model

# def settings_view(request):
#     if not request.session.get("user_email"):
#         return redirect("login")

#     # Get user_id from session
#     user_id = request.session["user_id"]

#     # Ensure that user_id is UUID type (if not, you might need to cast it)
#     try:
#         # Convert user_id to UUID if it isn't already
#         user_id = UUID(user_id)
#     except ValueError:
#         messages.error(request, "Invalid user ID format.")
#         return redirect("login")

#     # Fetch user from the custom user model
#     user = User.objects.filter(id=user_id).first()

#     if not user:
#         messages.error(request, "User not found.")
#         return redirect("login")

#     # Handle form submission
#     if request.method == 'POST':
#         # Get form data
#         first_name = request.POST.get('first_name')
#         last_name = request.POST.get('last_name')
#         profile_image = request.FILES.get('profile_image')

#         # Validation for first name and last name
#         if len(first_name) < 2 or len(last_name) < 2:
#             messages.error(request, "First and Last name must be at least 2 characters long.")
#             return redirect("settings")

#         # Update user data
#         user.first_name = first_name
#         user.last_name = last_name

#         # Handle profile image upload
#         if profile_image:
#             # Save the uploaded image
#             fs = FileSystemStorage()
#             filename = fs.save(profile_image.name, profile_image)
#             user.profile_image = fs.url(filename)

#         user.save()  # Save the updated user information

#         messages.success(request, "Profile updated successfully.")
#         return redirect("settings")

#     # Fetch user data to pre-fill the form
#     full_name = f"{user.first_name} {user.last_name}".strip()
#     first_name = user.first_name
#     last_name = user.last_name
#     email = user.email
#     profile_image = user.profile_image
#     # Generate initials from first_name and last_name
#     first_initial = user.first_name[:1] if user.first_name else ""
#     last_initial = user.last_name[:1] if user.last_name else ""
#     initials = (first_initial + last_initial).upper()


#     context = {
#         "full_name": full_name,
#         "first_name": first_name,
#         "last_name": last_name,
#         "email": email,
#         "profile_image": profile_image,
#         "initials": initials,
#         "current_page": "settings",
#     }

#     return render(request, "user/user_settings.html", context)


# from supabase import create_client, Client
# import io
# import os

# Initialize Supabase client
# supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

import uuid
from datetime import datetime
from django.core.files.storage import default_storage
from django.core.files.base import ContentFile

# Create the Supabase client
# supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

def settings_view(request):
    if not request.session.get("user_email"):
        return redirect("login")

    # Get user_id from session
    user_id = request.session["user_id"]

    # Ensure that user_id is UUID type (if not, you might need to cast it)
    try:
        user_id = UUID(user_id)
    except ValueError:
        messages.error(request, "Invalid user ID format.")
        return redirect("login")

    # Fetch user from the custom user model
    user = User.objects.filter(id=user_id).first()

    if not user:
        messages.error(request, "User not found.")
        return redirect("login")

    # Handle form submission
    if request.method == 'POST':
        # Get form data
        first_name = request.POST.get('first_name')
        last_name = request.POST.get('last_name')
        profile_image = request.FILES.get('profile_image')

        # Validation for first name and last name
        if len(first_name) < 2 or len(last_name) < 2:
            messages.error(request, "First and Last name must be at least 2 characters long.")
            return redirect("settings")

        # Update user data
        user.first_name = first_name
        user.last_name = last_name

        # Handle profile image upload to Supabase
        if profile_image:
            # Read the image data
            image_data = profile_image.read()

            # Generate a unique filename using UUID
            unique_id = uuid.uuid4()  # Use UUID for uniqueness
            file_extension = profile_image.name.split('.')[-1]  # Get the file extension
            file_name = f"{user.id}_{unique_id}.{file_extension}"  # Unique filename with UUID
            storage_path = f"profile_images/{file_name}"

            try:
                # Upload the image to Supabase
                response = supabase.storage.from_("profile-pictures").upload(storage_path, image_data)

                # Check if the upload was successful
                if response.get("data"):
                    # Get the public URL of the uploaded image
                    public_url = response["data"]["publicURL"]
                    user.profile_image = public_url  # Save the URL to the user's profile image field
                    user.save()

                    messages.success(request, "Profile image uploaded successfully.")
                else:
                    # If the response contains an error, handle it
                    error_message = response.get("error", {}).get("message", "Unknown error")
                    messages.error(request, f"Failed to upload profile image: {error_message}")
            
            except Exception as e:
                # Handle any exception that occurs during upload
                print(f"Error uploading file: {e}")
                messages.error(request, f"There was an error uploading the profile image: {e}")
    
        else:
            messages.error(request, "No profile image selected.")

        return redirect("settings")

    # Fetch user data to pre-fill the form
    full_name = f"{user.first_name} {user.last_name}".strip()
    first_name = user.first_name
    last_name = user.last_name
    email = user.email
    profile_image = user.profile_image

    # Generate initials from first_name and last_name
    first_initial = user.first_name[:1] if user.first_name else ""
    last_initial = user.last_name[:1] if user.last_name else ""
    initials = (first_initial + last_initial).upper()

    context = {
        "full_name": full_name,
        "first_name": first_name,
        "last_name": last_name,
        "email": email,
        "profile_image": profile_image,
        "initials": initials,
        "current_page": "settings",
    }

    return render(request, "user/user_settings.html", context)

def delete_account(request):
    if not request.session.get("user_id"):
        return redirect("login")

    user_id = request.session["user_id"]

    # Delete from custom users table
    supabase.table("users").delete().eq("id", user_id).execute()

    # Optional: delete profile images folder
    supabase.storage.from_("leaf-images").remove([f"profiles/{user_id}"])

    request.session.flush()
    messages.success(request, "Your account has been deleted successfully.")

    return redirect("home")

def analysis_history_view(request):
    if not request.session.get("user_email"):
        return redirect("login")

def forgot_password(request):
    if request.method == "POST":
        email = request.POST.get("email", "").strip()
        errors = {}

        if not email:
            errors["email"] = "Email is required."
        else:
            user_check = supabase.table("users").select("email").eq("email", email).execute()
            if not user_check.data:
                errors["email"] = "No account with this email."

        if errors:
            return render(request, "auth/forgot_password.html", {
                "errors": errors,
                "email": email,
            })
        
        token = generate_password_reset_token(email)
        domain = "127.0.0.1:8000" if settings.DEBUG else get_current_site(request).domain
        reset_link = f"http://{domain}/auth/forgot-password/?token={token}"

        subject = "LeafBuddy Password Reset"
        from_email = "no-reply@leafbuddy.com"
        to = [email]

        html_content = render_to_string("auth/reset_password_email.html", {
            "reset_link": reset_link,
        })
        text_content = strip_tags(html_content)

        email_message = EmailMultiAlternatives(subject, text_content, from_email, to)
        email_message.attach_alternative(html_content, "text/html")
        email_message.send()

        # messages.success(request, "Password reset link has been sent to your email.")
        return render(request, "auth/reset_link_sent.html", {
            "user_email": email,
        })

    return render(request, "auth/forgot_password.html")

