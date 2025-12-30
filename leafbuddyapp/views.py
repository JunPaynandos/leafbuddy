from django.shortcuts import render, redirect, get_object_or_404
import os, json, bcrypt, requests
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from .password_reset_utils import generate_password_reset_token
from django.contrib.auth.tokens import default_token_generator
from django.contrib.sites.shortcuts import get_current_site
from django.core.files.storage import default_storage
from django.views.decorators.csrf import csrf_exempt
from django.core.mail import EmailMultiAlternatives
from django.template.loader import render_to_string
from datetime import datetime, timezone, timedelta
from django.contrib.auth import get_user_model
from django.utils.encoding import force_bytes
from .utils.supabase_user import SupabaseUser
from .utils.hf_client import predict_with_hf
from django.contrib.auth.models import User
from django.utils.html import strip_tags
from django.core.mail import send_mail
from django.http import JsonResponse
from leafbuddyapp.models import Crop 
from django.contrib import messages
from .models import AnalysisHistory
from mimetypes import guess_type
from supabase import create_client
from django.utils import timezone
from django.conf import settings
from django.urls import reverse
from dateutil import parser
from uuid import UUID
import tempfile
import logging
import uuid

logger = logging.getLogger(__name__)

SUPABASE_URL = settings.SUPABASE_URL
SUPABASE_SERVICE_ROLE_KEY = settings.SUPABASE_SERVICE_ROLE_KEY

supabase = create_client(settings.SUPABASE_URL, settings.SUPABASE_SERVICE_ROLE_KEY)

DISEASE_JSON_PATH = os.path.join(settings.BASE_DIR, "data", "disease_info.json")
with open(DISEASE_JSON_PATH, "r") as f:
    DISEASE_DATA = json.load(f)

User = get_user_model()

GUEST_SCAN_LIMIT = 5

def home(request):
    return render(request, 'user/index.html', {'current_page': 'home'})

def scan(request):
    # Fetch crops
    try:
        crops_res = supabase.table("leafbuddyapp_crop").select("*").execute()
        crops = crops_res.data or []
    except Exception:
        logger.exception("❌ Failed to fetch crops from Supabase")
        return render(request, "user/scan.html", {
            "crops": [],
            "error": "Failed to load crops."
        })

    # Guest limit (RESET AT MIDNIGHT)
    is_guest = "user_id" not in request.session
    guest_limit_reached = False

    if is_guest:
        today = timezone.localdate()
        stored_date = request.session.get("guest_scan_date")
        scan_count = request.session.get("guest_scan_count", 0)

        # Reset every midnight
        if stored_date != str(today):
            scan_count = 0
            request.session["guest_scan_date"] = str(today)

        request.session["guest_scan_count"] = scan_count

        if scan_count >= GUEST_SCAN_LIMIT:
            guest_limit_reached = True

    # POST → Scan
    if request.method == "POST":

        # Block guest if limit reached
        if is_guest and guest_limit_reached:
            return render(request, "user/scan.html", {
                "crops": crops,
                "guest_limit_reached": True,
                "remaining_scans": 0,
                "error": "Guest scan limit reached for today. Please log in to continue."
            })

        crop_name = request.POST.get("crop_type")
        leaf_image = request.FILES.get("leaf_image")

        if not crop_name or not leaf_image:
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": "Missing crop or image."
            })

        # Validate crop
        crop_data = next(
            (c for c in crops if c["name"].lower() == crop_name.lower()),
            None
        )

        if not crop_data:
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": "Invalid crop selected."
            })

        # Save temp file
        try:
            suffix = os.path.splitext(leaf_image.name)[1]
            with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                for chunk in leaf_image.chunks():
                    tmp.write(chunk)
                temp_full_path = tmp.name
        except Exception:
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": "Failed to process image."
            })

        # Upload to Supabase
        try:
            file_key = f"{crop_name.lower()}/{uuid.uuid4()}-{leaf_image.name}"
            content_type = guess_type(leaf_image.name)[0] or "application/octet-stream"

            with open(temp_full_path, "rb") as f:
                file_data = f.read()

            supabase.storage.from_("leaf-images").upload(
                file_key, file_data, {"content-type": content_type}
            )

            image_url = supabase.storage.from_("leaf-images").get_public_url(file_key)

        except Exception as e:
            os.unlink(temp_full_path)
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": f"Image upload failed: {e}"
            })

        # Predict via HF
        try:
            predicted_class, confidence = predict_with_hf(
                temp_full_path, crop_name
            )
        except Exception:
            os.unlink(temp_full_path)
            return render(request, "user/scan.html", {
                "crops": crops,
                "error": "Prediction failed."
            })

        os.unlink(temp_full_path)

        # Disease info
        disease_info = DISEASE_DATA.get(
            crop_name.lower(), {}
        ).get(predicted_class.lower(), {})

        # Save history
        if "user_id" in request.session:
            try:
                django_crop = Crop.objects.get(name__iexact=crop_name)
                AnalysisHistory.objects.create(
                    user_id=request.session["user_id"],
                    crop=django_crop,
                    image_url=image_url,
                    predicted_class=predicted_class,
                    confidence=round(confidence * 100, 2),
                    description=disease_info.get("description", ""),
                    symptoms=disease_info.get("symptoms", ""),
                    treatment=disease_info.get("treatment", ""),
                    prevention=disease_info.get("prevention", ""),
                )
            except Exception:
                logger.exception("❌ Failed to save history")

        # Increment guest count
        if is_guest:
            request.session["guest_scan_count"] += 1
            request.session.modified = True

        # Save result
        request.session["scan_result"] = {
            "result": predicted_class,
            "confidence": round(confidence * 100, 2),
            "crop": crop_name.capitalize(),
            "image_url": image_url,
            **disease_info
        }

        return redirect("result")

    # GET
    return render(request, "user/scan.html", {
        "crops": crops,
        "current_page": "features",
        "guest_limit_reached": guest_limit_reached,
        "remaining_scans": max(
            0, GUEST_SCAN_LIMIT - request.session.get("guest_scan_count", 0)
        ),
    })

def result(request):
    data = request.session.pop("scan_result", None)
    if not data:
        return redirect("scan")

    return render(request, "user/result.html", {**data, "current_page": "features"})

@csrf_exempt
def predict_frame(request):
    if request.method != "POST":
        return JsonResponse({"error": "Invalid request method"}, status=405)

    is_guest = "user_id" not in request.session

    # Guest limit (RESET AT MIDNIGHT)
    if is_guest:
        today = timezone.localdate()
        stored_date = request.session.get("guest_scan_date")
        scan_count = request.session.get("guest_scan_count", 0)

        if stored_date != str(today):
            scan_count = 0
            request.session["guest_scan_date"] = str(today)

        request.session["guest_scan_count"] = scan_count

        if scan_count >= GUEST_SCAN_LIMIT:
            return JsonResponse({
                "error": "Guest scan limit reached for today. Please log in to continue.",
                "remaining_attempts": 0
            }, status=403)

    crop_name = request.POST.get("crop_type")
    image_file = request.FILES.get("frame")

    if not crop_name or not image_file:
        return JsonResponse({"error": "Missing crop_type or frame"}, status=400)

    # Save frame
    with tempfile.NamedTemporaryFile(delete=False, suffix=".jpg") as tmp:
        for chunk in image_file.chunks():
            tmp.write(chunk)
        temp_path = tmp.name

    # Predict viw HF
    try:
        predicted_class, confidence = predict_with_hf(temp_path, crop_name)
    except Exception as e:
        os.unlink(temp_path)
        return JsonResponse({"error": f"Prediction failed: {e}"}, status=500)

    os.unlink(temp_path)

    # Increment guest count
    if is_guest:
        request.session["guest_scan_count"] += 1
        request.session.modified = True
        remaining_attempts = max(
            0, GUEST_SCAN_LIMIT - request.session["guest_scan_count"]
        )
    else:
        remaining_attempts = None

    return JsonResponse({
        "disease": predicted_class,
        "confidence": round(confidence * 100, 2),
        "remaining_attempts": remaining_attempts
    })

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
    json_file_path = os.path.join(settings.BASE_DIR, "data", "disease_images.json")
    
    try:
        with open(json_file_path, 'r') as file:
            return json.load(file)  # Returns a dictionary
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
            disease_image = disease_data.get('image')
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

    is_healthy = "healthy" in disease_name.lower() or disease_name.lower() == "undefined"

    disease_image = disease.get('image')

    disease_images = load_disease_images()
    related_images = disease_images.get(disease_name.lower(), [])

    context = {
        "crop_name": crop_name.capitalize(),
        "disease_name": disease_name.capitalize(),
        "is_healthy": is_healthy,
        "image_path": disease_image,
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

        email_subject = f"New Contact Message from {name}"
        email_message = f"""
You received a new message from your website contact form.

Name: {name}
Email: {email}

Message:
{message}
        """

        send_mail(
            email_subject,
            email_message,
            settings.DEFAULT_FROM_EMAIL,
            ['leafbuddy8@gmail.com'],  # where you receive the message
            fail_silently=False,
        )

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
        mock_user = SupabaseUser(user_dict)

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
            "last_login": timezone.now().isoformat()
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

    # Query by email
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
            "last_login": timezone.now().isoformat()
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
            "last_login": timezone.now().isoformat()
        }]).execute()

        user = insert.data[0]

    initials = (user.get("first_name", "")[:1] + user.get("last_name", "")[:1]).upper()

    request.session["user_id"] = user["id"]
    request.session["user_email"] = user["email"]
    request.session["user_name"] = f"{user.get('first_name', '')} {user.get('last_name', '')}".strip()
    request.session["profile_image"] = user.get("profile_image")
    request.session["initials"] = initials

    if user.get("password") is None:
        messages.info(request, "You signed in with Google. Set a password to enable email login.")
        return redirect("set_password")

    return redirect("home")

def settings_view(request):
    if not request.session.get("user_email"):
        return redirect("login")

    user_id = request.session["user_id"]

    try:
        user_id = UUID(user_id)
    except ValueError:
        messages.error(request, "Invalid user ID format.")
        return redirect("login")

    user = User.objects.filter(id=user_id).first()
    if not user:
        messages.error(request, "User not found.")
        return redirect("login")

    # Fetch analysis history for current user
    analyses = AnalysisHistory.objects.filter(user_id=str(user.id)).order_by("-created_at")
    total_scans = analyses.count()
    latest_scans = AnalysisHistory.objects.filter(user_id=str(user.id)).order_by("-created_at")[:3]

    context = {
        "user": user,
        "first_name": user.first_name,
        "last_name": user.last_name,
        "email": user.email,
        "profile_image": user.profile_image,
        "initials": (user.first_name[:1] + user.last_name[:1]).upper(),
        "total_scans": total_scans,
        "latest_scans": latest_scans,
        "current_page": "settings",
    }

    return render(request, "user/user_settings.html", context)

def delete_account(request):
    if not request.session.get("user_id"):
        return redirect("login")

    user_id = request.session["user_id"]

    # Delete from custom users table
    supabase.table("users").delete().eq("id", user_id).execute()

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
