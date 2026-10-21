import os

import re

import secrets

import logging

from datetime import datetime, timedelta

from urllib.parse import quote

from functools import wraps


import mysql.connector

import requests

from dotenv import load_dotenv

from flask import (

    Flask, render_template, render_template_string, request, redirect,

    url_for, session, flash, jsonify

)

load_dotenv()

app = Flask(__name__)

app.secret_key = os.getenv("FLASK_SECRET_KEY", "replace-this-secret")

logging.basicConfig(level=logging.INFO)

DB_CONFIG = {

    "host": os.getenv("DB_HOST", "127.0.0.1"),

    "port": int(os.getenv("DB_PORT", "3306")),

    "user": os.getenv("DB_USER", "root"),

    "password": os.getenv("DB_PASSWORD", ""),

    "database": os.getenv("DB_NAME", "campusride_db"),

    "autocommit": False,

}

OTP_ENABLED = os.getenv("OTP_ENABLED", "0").strip() == "1"

OTP_API_KEY = os.getenv("TWOFACTOR_API_KEY", "").strip()

OTP_TEMPLATE = os.getenv("TWOFACTOR_OTP_TEMPLATE", "").strip()

OTP_BASE = "https://2factor.in/API/V1"

# ==================================================

# DATABASE

# ==================================================

def get_db_connection():

    return mysql.connector.connect(**DB_CONFIG)

def normalize_phone(value):

    digits = re.sub(r"\D", "", value or "")

    if digits.startswith("91") and len(digits) == 12:

        digits = digits[2:]

    if len(digits) != 10 or digits[0] not in "6789":

        raise ValueError("Enter a valid 10-digit Indian mobile number.")

    return "+91" + digits

def get_current_rider():

    rider_id = session.get("rider_id")

    if not rider_id:

        return None

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            """

            SELECT rider_id, student_code, name, phone, email

            FROM RIDER

            WHERE rider_id = %s

            """,

            (rider_id,),

        )

        return cursor.fetchone()

    finally:

        cursor.close()

        conn.close()

def get_current_driver():

    driver_id = session.get("driver_id")

    if not driver_id:

        return None

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            """

            SELECT driver_id, name, phone, status

            FROM DRIVER

            WHERE driver_id = %s

            """,

            (driver_id,),

        )

        return cursor.fetchone()

    finally:

        cursor.close()

        conn.close()

def driver_login_required(view):

    @wraps(view)

    def wrapped_view(*args, **kwargs):

        if not session.get("driver_id"):

            flash("Please log in as a driver first.", "error")

            return redirect(url_for("driver_login"))

        return view(*args, **kwargs)

    return wrapped_view

def login_required():

    return bool(session.get("rider_id"))

def get_route(cursor, source_id, destination_id):

    cursor.execute(

        """

        SELECT route_id, distance_km,

               estimated_duration_minutes, base_fare

        FROM ROUTE

        WHERE source_location_id = %s

          AND destination_location_id = %s

          AND active = TRUE

        """,

        (source_id, destination_id),

    )

    return cursor.fetchone()

# ==================================================

# 2FACTOR OTP

# ==================================================

def send_otp(phone):

    if not OTP_ENABLED:

        raise RuntimeError("OTP_ENABLED is not set to 1.")

    if not OTP_API_KEY:

        raise RuntimeError("Missing 2Factor API key.")

    phone = normalize_phone(phone)

    endpoint = (

        f"{OTP_BASE}/{quote(OTP_API_KEY, safe='')}"

        f"/SMS/{quote(phone, safe='')}/AUTOGEN"

    )

    if OTP_TEMPLATE:

        endpoint += "/" + quote(OTP_TEMPLATE, safe="")

    response = requests.get(endpoint, timeout=20)

    response.raise_for_status()

    data = response.json()

    if str(data.get("Status", "")).lower() != "success":

        app.logger.warning("2Factor send failed: %s", data.get("Details"))

        raise RuntimeError("2Factor could not send OTP.")

    provider_id = data.get("Details")

    if not provider_id:

        raise RuntimeError("2Factor did not return a session ID.")

    return provider_id

def verify_otp(provider_id, otp):

    if not OTP_ENABLED or not OTP_API_KEY:

        raise RuntimeError("OTP verification is not configured.")

    otp = str(otp or "").strip()

    if not re.fullmatch(r"\d{6}", otp):

        return False

    endpoint = (

        f"{OTP_BASE}/{quote(OTP_API_KEY, safe='')}"

        f"/SMS/VERIFY/{quote(str(provider_id), safe='')}"

        f"/{quote(otp, safe='')}"

    )

    response = requests.get(endpoint, timeout=20)

    response.raise_for_status()

    data = response.json()

    return str(data.get("Status", "")).lower() == "success"

def create_otp_challenge(phone, name, provider_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(

            """

            INSERT INTO OTP_CHALLENGE

                (phone, student_name, provider_session_id,

                 expires_at, attempts, last_sent_at, consumed_at)

            VALUES (%s, %s, %s, %s, 0, %s, NULL)

            """,

            (

                phone,

                name,

                provider_id,

                datetime.now() + timedelta(minutes=5),

                datetime.now(),

            ),

        )

        conn.commit()

        return cursor.lastrowid

    except Exception:

        conn.rollback()

        raise

    finally:

        cursor.close()

        conn.close()

def get_otp_challenge(challenge_id):

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            """

            SELECT *

            FROM OTP_CHALLENGE

            WHERE challenge_id = %s

            """,

            (challenge_id,),

        )

        return cursor.fetchone()

    finally:

        cursor.close()

        conn.close()

def increment_otp_attempts(challenge_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(

            """

            UPDATE OTP_CHALLENGE

            SET attempts = attempts + 1

            WHERE challenge_id = %s AND consumed_at IS NULL

            """,

            (challenge_id,),

        )

        conn.commit()

    except Exception:

        conn.rollback()

        raise

    finally:

        cursor.close()

        conn.close()

def consume_otp_challenge(challenge_id):

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(

            """

            UPDATE OTP_CHALLENGE

            SET consumed_at = %s

            WHERE challenge_id = %s AND consumed_at IS NULL

            """,

            (datetime.now(), challenge_id),

        )

        conn.commit()

        return cursor.rowcount == 1

    except Exception:

        conn.rollback()

        raise

    finally:

        cursor.close()

        conn.close()

# ==================================================

# HOME AND HEALTH

# ==================================================

@app.route("/")
def index():
    # Always show role selection first; dashboard access remains session-protected.
    return render_template("index.html")

@app.route("/health")

def health():

    try:

        conn = get_db_connection()

        conn.close()

        return jsonify(status="ok", database=DB_CONFIG["database"])

    except mysql.connector.Error:

        app.logger.exception("Database health check failed")

        return jsonify(status="error", database="unavailable"), 500

# ==================================================

# REGISTRATION

# ==================================================

@app.route("/register", methods=["GET", "POST"])

def register():

    if request.method == "GET":

        return render_template("login.html", mode="register")

    name = request.form.get("name", "").strip()

    email = request.form.get("email", "").strip() or None

    if not name or len(name) > 100:

        flash("Enter a valid name.", "error")

        return redirect(url_for("register"))

    try:

        phone = normalize_phone(request.form.get("phone", ""))

    except ValueError as exc:

        flash(str(exc), "error")

        return redirect(url_for("register"))

    if email and not re.fullmatch(

        r"[^@\s]+@[^@\s]+**\.**[^@\s]+", email

    ):

        flash("Enter a valid email address.", "error")

        return redirect(url_for("register"))

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            "SELECT rider_id FROM RIDER WHERE phone = %s",

            (phone,),

        )

        if cursor.fetchone():

            flash("Phone already registered. Please log in.", "error")

            return redirect(url_for("login"))

        if email:

            cursor.execute(

                "SELECT rider_id FROM RIDER WHERE email = %s",

                (email,),

            )

            if cursor.fetchone():

                flash("Email already registered.", "error")

                return redirect(url_for("register"))

    finally:

        cursor.close()

        conn.close()

    try:

        provider_id = send_otp(phone)

        challenge_id = create_otp_challenge(phone, name, provider_id)

    except (RuntimeError, requests.RequestException, mysql.connector.Error):

        app.logger.exception("Could not start registration OTP")

        flash("Could not send OTP. Check your 2Factor configuration.", "error")

        return redirect(url_for("register"))

    session["otp_challenge_id"] = challenge_id

    session["otp_flow"] = "register"

    session["pending_email"] = email

    flash("OTP sent to your phone.", "success")

    return redirect(url_for("verify_registration"))

@app.route("/verify-registration", methods=["GET", "POST"])

def verify_registration():

    if session.get("otp_flow") != "register":

        flash("Start registration first.", "error")

        return redirect(url_for("register"))

    challenge_id = session.get("otp_challenge_id")

    challenge = get_otp_challenge(challenge_id) if challenge_id else None

    if not challenge or challenge["consumed_at"]:

        session.pop("otp_challenge_id", None)

        flash("OTP request is invalid. Please start again.", "error")

        return redirect(url_for("register"))

    if datetime.now() > challenge["expires_at"]:

        session.pop("otp_challenge_id", None)

        flash("OTP expired. Please register again.", "error")

        return redirect(url_for("register"))

    if request.method == "GET":

        return render_template(

            "login.html", mode="verify", phone=challenge["phone"]

        )

    if challenge["attempts"] >= 5:

        session.clear()

        flash("Too many OTP attempts. Start again.", "error")

        return redirect(url_for("register"))

    try:

        valid = verify_otp(

            challenge["provider_session_id"],

            request.form.get("otp", ""),

        )

    except (RuntimeError, requests.RequestException):

        app.logger.exception("Registration OTP verification failed")

        flash("OTP service failed. Please try again.", "error")

        return redirect(url_for("verify_registration"))

    if not valid:

        increment_otp_attempts(challenge_id)

        flash("Incorrect OTP. Try again.", "error")

        return redirect(url_for("verify_registration"))

    # Consume the challenge exactly once.

    if not consume_otp_challenge(challenge_id):

        flash("This OTP was already used. Start again.", "error")

        return redirect(url_for("register"))

    student_code = "CR" + secrets.token_hex(4).upper()

    email = session.get("pending_email")

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(

            """

            INSERT INTO RIDER (student_code, name, phone, email)

            VALUES (%s, %s, %s, %s)

            """,

            (student_code, challenge["student_name"], challenge["phone"], email),

        )

        rider_id = cursor.lastrowid

        conn.commit()

    except mysql.connector.Error:

        conn.rollback()

        app.logger.exception("Could not create rider")

        flash("Could not create account. Phone or email may already exist.", "error")

        return redirect(url_for("register"))

    finally:

        cursor.close()

        conn.close()

    session.clear()

    session["rider_id"] = rider_id

    flash("Phone verified. Welcome to CampusRide!", "success")

    return redirect(url_for("dashboard"))

# ==================================================

# LOGIN

# ==================================================

@app.route("/login", methods=["GET", "POST"])

def login():

    if login_required():

        return redirect(url_for("dashboard"))

    if request.method == "GET":

        return render_template("login.html", mode="login")

    try:

        phone = normalize_phone(request.form.get("phone", ""))

    except ValueError as exc:

        flash(str(exc), "error")

        return redirect(url_for("login"))

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            "SELECT rider_id FROM RIDER WHERE phone = %s",

            (phone,),

        )

        rider = cursor.fetchone()

    finally:

        cursor.close()

        conn.close()

    if not rider:

        flash("Account not found. Please register first.", "error")

        return redirect(url_for("register"))

    try:

        provider_id = send_otp(phone)

        challenge_id = create_otp_challenge(phone, "", provider_id)

    except (RuntimeError, requests.RequestException, mysql.connector.Error):

        app.logger.exception("Could not start login OTP")

        flash("Could not send login OTP.", "error")

        return redirect(url_for("login"))

    session["otp_challenge_id"] = challenge_id

    session["otp_flow"] = "login"

    flash("Login OTP sent.", "success")

    return redirect(url_for("verify_login"))

@app.route("/verify-login", methods=["GET", "POST"])

def verify_login():

    if session.get("otp_flow") != "login":

        flash("Request a login OTP first.", "error")

        return redirect(url_for("login"))

    challenge_id = session.get("otp_challenge_id")

    challenge = get_otp_challenge(challenge_id) if challenge_id else None

    if not challenge or challenge["consumed_at"]:

        session.clear()

        flash("OTP request is invalid. Please log in again.", "error")

        return redirect(url_for("login"))

    if datetime.now() > challenge["expires_at"]:

        session.clear()

        flash("OTP expired. Please log in again.", "error")

        return redirect(url_for("login"))

    if request.method == "GET":

        return render_template(

            "login.html", mode="verify_login", phone=challenge["phone"]

        )

    if challenge["attempts"] >= 5:

        session.clear()

        flash("Too many OTP attempts. Please log in again.", "error")

        return redirect(url_for("login"))

    try:

        valid = verify_otp(

            challenge["provider_session_id"],

            request.form.get("otp", ""),

        )

    except (RuntimeError, requests.RequestException):

        app.logger.exception("Login OTP verification failed")

        flash("OTP service failed. Please try again.", "error")

        return redirect(url_for("verify_login"))

    if not valid:

        increment_otp_attempts(challenge_id)

        flash("Incorrect OTP. Try again.", "error")

        return redirect(url_for("verify_login"))

    if not consume_otp_challenge(challenge_id):

        flash("This OTP was already used. Please log in again.", "error")

        return redirect(url_for("login"))

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            "SELECT rider_id FROM RIDER WHERE phone = %s",

            (challenge["phone"],),

        )

        rider = cursor.fetchone()

    finally:

        cursor.close()

        conn.close()

    session.clear()

    if not rider:

        flash("Account not found. Please register.", "error")

        return redirect(url_for("register"))

    session["rider_id"] = rider["rider_id"]

    flash("Login successful.", "success")

    return redirect(url_for("dashboard"))

@app.route("/logout")

def logout():

    session.clear()

    return redirect(url_for("login"))

# ==================================================

# DASHBOARD

# ==================================================

# -------------------- DASHBOARD + AVAILABILITY SEARCH --------------------

@app.route("/dashboard")

def dashboard():

    rider = get_current_rider()

    if not rider:

        session.clear()

        return redirect(url_for("login"))

    pickup_id = request.args.get("pickup_id", type=int)

    drop_id = request.args.get("drop_id", type=int)

    party_size = request.args.get("party_size", default=1, type=int)

    departure_text = request.args.get("departure", "").strip()

    if party_size < 1 or party_size > 8:

        party_size = 1

    locations = []

    route = None

    drivers = []

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        # Load locations for the search dropdowns.

        cursor.execute("""

            SELECT location_id, location_name, category

            FROM LOCATION

            WHERE active = TRUE

            ORDER BY location_name

        """)

        locations = cursor.fetchall()

        # Search only when all required search fields are provided.

        if pickup_id and drop_id and departure_text:

            try:

                departure = datetime.fromisoformat(departure_text)

            except ValueError:

                departure = None

                flash("Choose a valid departure date and time.", "error")

            if departure:

                if pickup_id == drop_id:

                    flash(

                        "Pickup and drop-off must be different.",

                        "error"

                    )

                elif departure < datetime.now() - timedelta(minutes=1):

                    flash(

                        "Departure cannot be in the past.",

                        "error"

                    )

                else:

                    route_row = get_route(cursor, pickup_id, drop_id)

                    if not route_row:

                        flash(

                            "No route exists between these locations.",

                            "error"

                        )

                    else:

                        # Get pickup and drop-off names.

                        cursor.execute("""

                            SELECT location_id, location_name

                            FROM LOCATION

                            WHERE location_id IN (%s, %s)

                        """, (pickup_id, drop_id))

                        names = {

                            row["location_id"]: row["location_name"]

                            for row in cursor.fetchall()

                        }

                        route = {

                            "pickup": names.get(pickup_id, "Pickup"),

                            "dropoff": names.get(drop_id, "Drop-off"),

                            "distance_km": route_row["distance_km"],

                            "estimated_duration_minutes":

                                route_row["estimated_duration_minutes"]

                        }

                        duration = int(

                            route_row["estimated_duration_minutes"]

                        )

                        requested_end = departure + timedelta(

                            minutes=duration

                        )

                        # Find drivers whose vehicles have enough seats

                        # and who have no overlapping ride.

                        cursor.execute("""

                            SELECT

                                d.driver_id,

                                d.name AS driver_name,

                                v.vehicle_id,

                                v.vehicle_type,

                                v.registration_no,

                                v.capacity

                            FROM DRIVER d

                            JOIN VEHICLE v

                                ON v.driver_id = d.driver_id

                            WHERE d.status = 'AVAILABLE'

                              AND v.capacity >= %s

                              AND NOT EXISTS (

                                  SELECT 1

                                  FROM RIDE r

                                  WHERE r.driver_id = d.driver_id

                                    AND r.status IN (

                                        'REQUESTED', 'ACCEPTED', 'ONGOING'

                                    )

                                    AND r.ride_time < %s

                                    AND DATE_ADD(

                                        r.ride_time,

                                        INTERVAL r.duration_minutes MINUTE

                                    ) > %s

                              )

                            ORDER BY d.driver_id

                        """, (

                            party_size,

                            requested_end,

                            departure

                        ))

                        for driver in cursor.fetchall():

                            driver["departure"] = departure

                            driver["duration_minutes"] = duration

                            driver["fare"] = float(

                                route_row["base_fare"]

                            )

                            drivers.append(driver)

                        if not drivers:

                            flash(

                                "No drivers are available for that time "

                                "and passenger count.",

                                "error"

                            )

    except mysql.connector.Error:

        app.logger.exception("Availability search failed")

        flash(

            "Could not search availability. Check the VS Code terminal.",

            "error"

        )

    finally:

        cursor.close()

        conn.close()

    return render_template(

        "dashboard.html",

        rider=rider,

        locations=locations,

        pickup_id=pickup_id,

        drop_id=drop_id,

        party_size=party_size,

        departure_text=departure_text,

        route=route,

        drivers=drivers

    )

# ==================================================

# AVAILABILITY + ATOMIC BOOKING

# ==================================================

# -------------------- BOOK SELECTED DRIVER --------------------

@app.route("/book", methods=["POST"])

def book():

    rider = get_current_rider()

    if not rider:

        session.clear()

        return redirect(url_for("login"))

    # These names must match the hidden fields in dashboard.html.

    driver_id = request.form.get("driver_id", type=int)

    vehicle_id = request.form.get("vehicle_id", type=int)

    pickup_id = request.form.get("pickup_id", type=int)

    drop_id = request.form.get("drop_id", type=int)

    party_size = request.form.get("party_size", type=int) or 1

    departure_text = request.form.get("departure", "").strip()

    if (

        not driver_id

        or not vehicle_id

        or not pickup_id

        or not drop_id

        or pickup_id == drop_id

    ):

        flash("Invalid booking details. Search again.", "error")

        return redirect(url_for("dashboard"))

    if not 1 <= party_size <= 8:

        flash(

            "Passenger count must be between 1 and 8.",

            "error"

        )

        return redirect_to_search(

            pickup_id, drop_id, departure_text, party_size

        )

    try:

        departure = datetime.fromisoformat(departure_text)

    except ValueError:

        flash("Invalid departure time. Search again.", "error")

        return redirect_to_search(

            pickup_id, drop_id, departure_text, party_size

        )

    if departure < datetime.now() - timedelta(minutes=1):

        flash("Departure cannot be in the past.", "error")

        return redirect_to_search(

            pickup_id, drop_id, departure_text, party_size

        )

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        conn.start_transaction()

        # Confirm that the selected route still exists.

        route_row = get_route(cursor, pickup_id, drop_id)

        if not route_row:

            conn.rollback()

            flash("This route is no longer available.", "error")

            return redirect_to_search(

                pickup_id, drop_id, departure_text, party_size

            )

        duration = int(

            route_row["estimated_duration_minutes"]

        )

        fare = float(route_row["base_fare"])

        requested_end = departure + timedelta(

            minutes=duration

        )

        # Lock the selected driver to reduce simultaneous bookings.

        cursor.execute("""

            SELECT driver_id, status

            FROM DRIVER

            WHERE driver_id = %s

            FOR UPDATE

        """, (driver_id,))

        driver = cursor.fetchone()

        if not driver or driver["status"] != "AVAILABLE":

            conn.rollback()

            flash(

                "This driver is no longer available. Search again.",

                "error"

            )

            return redirect_to_search(

                pickup_id, drop_id, departure_text, party_size

            )

        # Confirm that the selected vehicle belongs to this driver.

        # Also lock the vehicle while booking.

        cursor.execute("""

            SELECT vehicle_id, capacity

            FROM VEHICLE

            WHERE vehicle_id = %s

              AND driver_id = %s

            FOR UPDATE

        """, (vehicle_id, driver_id))

        vehicle = cursor.fetchone()

        if not vehicle:

            conn.rollback()

            flash(

                "The selected vehicle does not belong to this driver.",

                "error"

            )

            return redirect_to_search(

                pickup_id, drop_id, departure_text, party_size

            )

        if vehicle["capacity"] < party_size:

            conn.rollback()

            flash(

                "This vehicle does not have enough seats.",

                "error"

            )

            return redirect_to_search(

                pickup_id, drop_id, departure_text, party_size

            )

        # Recheck overlapping bookings immediately before inserting.

        cursor.execute("""

            SELECT ride_id

            FROM RIDE

            WHERE driver_id = %s

              AND status IN ('REQUESTED', 'ACCEPTED', 'ONGOING')

              AND ride_time < %s

              AND DATE_ADD(

                  ride_time,

                  INTERVAL duration_minutes MINUTE

              ) > %s

            LIMIT 1

            FOR UPDATE

        """, (

            driver_id,

            requested_end,

            departure

        ))

        overlapping_ride = cursor.fetchone()

        if overlapping_ride:

            conn.rollback()

            flash(

                "This driver was just booked for an overlapping time.",

                "error"

            )

            return redirect_to_search(

                pickup_id, drop_id, departure_text, party_size

            )

        # Insert the main ride.

        cursor.execute("""

            INSERT INTO RIDE (

                rider_id,

                driver_id,

                vehicle_id,

                pickup_location,

                drop_location,

                ride_time,

                duration_minutes,

                party_size,

                fare,

                status

            )

            VALUES (

                %s, %s, %s, %s, %s, %s, %s, %s, %s, 'REQUESTED'

            )

        """, (

            rider["rider_id"],

            driver_id,

            vehicle_id,

            pickup_id,

            drop_id,

            departure,

            duration,

            party_size,

            fare

        ))

        ride_id = cursor.lastrowid

        # Add the rider to the ride.

        cursor.execute("""

            INSERT INTO RIDE_RIDER (

                ride_id,

                rider_id,

                pickup_zone,

                drop_zone,

                fare_share

            )

            VALUES (%s, %s, %s, %s, %s)

        """, (

            ride_id,

            rider["rider_id"],

            pickup_id,

            drop_id,

            fare

        ))

        # Save both inserts together.

        conn.commit()

        flash(

            f"Ride #{ride_id} booked successfully! "

            f"Fare: ₹{fare:.2f}",

            "success"

        )

        return redirect(url_for("my_bookings"))

    except mysql.connector.Error:

        conn.rollback()

        app.logger.exception("Booking transaction failed")

        flash(

            "Database booking error. Check the VS Code terminal.",

            "error"

        )

        return redirect_to_search(

            pickup_id, drop_id, departure_text, party_size

        )

    finally:

        cursor.close()

        conn.close()

# ==================================================

# BOOKING HISTORY

# ==================================================

@app.route("/my-bookings")

def my_bookings():

    rider = get_current_rider()

    if not rider:

        session.clear()

        return redirect(url_for("login"))

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            """

            SELECT

                r.ride_id,

                r.ride_time,

                r.duration_minutes,

                r.party_size,

                r.fare,

                r.status,

                d.name AS driver_name,

                d.phone AS driver_phone,

                v.vehicle_type,

                v.registration_no,

                src.location_name AS pickup_name,

                dst.location_name AS drop_name

            FROM RIDE r

            JOIN DRIVER d ON d.driver_id = r.driver_id

            JOIN VEHICLE v ON v.vehicle_id = r.vehicle_id

            JOIN LOCATION src ON src.location_id = r.pickup_location

            JOIN LOCATION dst ON dst.location_id = r.drop_location

            WHERE r.rider_id = %s

            ORDER BY r.ride_time DESC

            """,

            (rider["rider_id"],),

        )

        bookings = cursor.fetchall()

        return render_template(

            "my_bookings.html",

            rider=rider,

            bookings=bookings,

        )

    finally:

        cursor.close()

        conn.close()

# -------------------- DRIVER LOGIN --------------------

@app.route("/driver-login", methods=["GET", "POST"])
def driver_login():
    if session.get("driver_id"):
        return redirect(url_for("driver_dashboard"))
    if request.method == "GET":
        return render_template("driver_login.html", otp_sent=False, phone="")
    try:
        phone = normalize_phone(request.form.get("phone", ""))
    except ValueError as exc:
        flash(str(exc), "error")
        return redirect(url_for("driver_login"))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT driver_id, name, phone, status FROM DRIVER WHERE phone = %s", (phone,))
        driver = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()
    if not driver:
        flash("No driver account is registered with that phone number.", "error")
        return redirect(url_for("driver_login"))
    if driver["status"] == "INACTIVE":
        flash("This driver account is inactive.", "error")
        return redirect(url_for("driver_login"))
    try:
        provider_id = send_otp(phone)
        challenge_id = create_otp_challenge(phone, "DRIVER", provider_id)
    except (RuntimeError, requests.RequestException, mysql.connector.Error):
        app.logger.exception("Could not start driver OTP")
        flash("Could not send OTP. Check your 2Factor configuration.", "error")
        return redirect(url_for("driver_login"))
    session["otp_challenge_id"] = challenge_id
    session["otp_flow"] = "driver_login"
    flash("Driver login OTP sent.", "success")
    return redirect(url_for("verify_driver_login"))

@app.route("/verify-driver-login", methods=["GET", "POST"])
def verify_driver_login():
    if session.get("otp_flow") != "driver_login":
        flash("Request a driver login OTP first.", "error")
        return redirect(url_for("driver_login"))
    challenge_id = session.get("otp_challenge_id")
    challenge = get_otp_challenge(challenge_id) if challenge_id else None
    if not challenge or challenge["consumed_at"]:
        session.clear()
        flash("OTP request is invalid. Please try again.", "error")
        return redirect(url_for("driver_login"))
    if datetime.now() > challenge["expires_at"]:
        session.clear()
        flash("OTP expired. Please request another OTP.", "error")
        return redirect(url_for("driver_login"))
    if request.method == "GET":
        return render_template("driver_login.html", otp_sent=True, phone=challenge["phone"])
    if challenge["attempts"] >= 5:
        session.clear()
        flash("Too many OTP attempts. Please request another OTP.", "error")
        return redirect(url_for("driver_login"))
    try:
        valid = verify_otp(challenge["provider_session_id"], request.form.get("otp", ""))
    except (RuntimeError, requests.RequestException):
        app.logger.exception("Driver OTP verification failed")
        flash("OTP service failed. Please try again.", "error")
        return redirect(url_for("verify_driver_login"))
    if not valid:
        increment_otp_attempts(challenge_id)
        flash("Incorrect OTP. Try again.", "error")
        return redirect(url_for("verify_driver_login"))
    if not consume_otp_challenge(challenge_id):
        flash("This OTP has already been used. Please log in again.", "error")
        return redirect(url_for("driver_login"))
    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT driver_id, status FROM DRIVER WHERE phone = %s", (challenge["phone"],))
        driver = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()
    session.clear()
    if not driver or driver["status"] == "INACTIVE":
        flash("Driver account is unavailable.", "error")
        return redirect(url_for("driver_login"))
    session["driver_id"] = driver["driver_id"]
    flash("Driver login successful.", "success")
    return redirect(url_for("driver_dashboard"))

# -------------------- DRIVER REGISTRATION (OTP VERIFIED) --------------------

DRIVER_REGISTER_TEMPLATE = r"""<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Register as Driver | CampusRide</title><link rel="stylesheet" href="{{ url_for('static', filename='css/style.css') }}">
<style>body{font-family:Arial,sans-serif;background:#f3f6fc}.reg-card{max-width:560px;margin:35px auto;background:#fff;padding:28px;border-radius:18px;box-shadow:0 12px 35px #0b1b3a12}.reg-card h1{margin-top:0;color:#102a56}.reg-card label{display:block;margin:14px 0 6px;font-weight:600}.reg-card input,.reg-card select{box-sizing:border-box;width:100%;padding:12px;border:1px solid #ccd5e4;border-radius:9px}.reg-card button{margin-top:20px;width:100%;padding:13px;border:0;border-radius:9px;background:#16a34a;color:#fff;font-weight:700;cursor:pointer}.hint{color:#5b6b83;font-size:14px;line-height:1.5}.reg-card a{color:#285cf6}</style></head>
<body><main class="reg-card"><h1>Register as a Driver</h1><p class="hint">Verify your phone with OTP. New driver accounts remain inactive until approved.</p>
{% with messages=get_flashed_messages(with_categories=true) %}{% for category,message in messages %}<p class="alert {{ category }}">{{ message }}</p>{% endfor %}{% endwith %}
<form method="post">
<label for="name">Full name</label><input id="name" name="name" maxlength="100" required value="{{ values.get('name','') }}">
<label for="phone">Mobile number</label><input id="phone" name="phone" inputmode="tel" maxlength="15" required value="{{ values.get('phone','') }}" placeholder="10-digit Indian mobile number">
<label for="license_no">Driving licence number</label><input id="license_no" name="license_no" maxlength="50" required value="{{ values.get('license_no','') }}">
<label for="registration_no">Vehicle registration number</label><input id="registration_no" name="registration_no" maxlength="30" required value="{{ values.get('registration_no','') }}">
<label for="vehicle_type">Vehicle type</label><select id="vehicle_type" name="vehicle_type" required><option value="">Select vehicle</option>{% for typ in ['Car','Bike','Auto','SUV','Van'] %}<option value="{{ typ }}" {% if values.get('vehicle_type')==typ %}selected{% endif %}>{{ typ }}</option>{% endfor %}</select>
<label for="capacity">Passenger capacity</label><input id="capacity" name="capacity" type="number" min="1" max="8" required value="{{ values.get('capacity','4') }}">
<button type="submit">Verify phone and register</button></form><p class="hint">Already registered? <a href="{{ url_for('driver_login') }}">Driver login</a></p><p class="hint"><a href="{{ url_for('index') }}">Back to CampusRide</a></p></main></body></html>"""


DRIVER_VERIFY_TEMPLATE = r"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Verify Driver OTP | CampusRide</title>
    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f1f5f9;
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
        }
        .card {
            background: white;
            width: 90%;
            max-width: 400px;
            padding: 30px;
            border-radius: 16px;
            box-shadow: 0 8px 30px rgba(0,0,0,.1);
            box-sizing: border-box;
        }
        h1 { color: #12315b; }
        p { color: #475569; line-height: 1.5; }
        label { display: block; margin: 20px 0 8px; font-weight: bold; }
        input {
            width: 100%;
            padding: 14px;
            box-sizing: border-box;
            border: 1px solid #cbd5e1;
            border-radius: 8px;
            font-size: 20px;
            letter-spacing: 5px;
        }
        button {
            width: 100%;
            padding: 14px;
            margin-top: 18px;
            border: 0;
            border-radius: 8px;
            background: #16a34a;
            color: white;
            font-size: 16px;
            font-weight: bold;
            cursor: pointer;
        }
        .message { margin-top: 15px; color: #b91c1c; }
        a { display: inline-block; margin-top: 18px; color: #2563eb; }
    </style>
</head>
<body>
    <main class="card">
        <h1>Verify your phone</h1>
        <p>Enter the six-digit OTP received on:</p>
        <p><strong>{{ phone }}</strong></p>

        {% with messages = get_flashed_messages(with_categories=true) %}
            {% for category, message in messages %}
                <p class="message">{{ message }}</p>
            {% endfor %}
        {% endwith %}

        <form method="POST"
              action="{{ url_for('verify_driver_registration') }}">
            <label for="otp">6-digit OTP</label>
            <input
                id="otp"
                name="otp"
                type="text"
                inputmode="numeric"
                pattern="[0-9]{6}"
                maxlength="6"
                autocomplete="one-time-code"
                placeholder="______"
                required
                autofocus
            >
            <button type="submit">Verify & Register</button>
        </form>

        <a href="{{ url_for('driver_register') }}">Back to registration</a>
    </main>
</body>
</html>
"""


@app.route("/driver-register", methods=["GET", "POST"])
def driver_register():
    if request.method == "GET":
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values={})

    name = request.form.get("name", "").strip()
    license_no = request.form.get("license_no", "").strip().upper()
    registration_no = request.form.get("registration_no", "").strip().upper()
    vehicle_type = request.form.get("vehicle_type", "").strip()
    try:
        phone = normalize_phone(request.form.get("phone", ""))
        capacity = int(request.form.get("capacity", "4"))
    except (ValueError, TypeError) as exc:
        flash(str(exc) if isinstance(exc, ValueError) else "Enter a valid passenger capacity.", "error")
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 400

    if not name or len(name) > 100 or not license_no or len(license_no) > 50 or not registration_no or len(registration_no) > 30:
        flash("Enter valid name, licence number, and vehicle registration number.", "error")
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 400
    if vehicle_type not in {"Car", "Bike", "Auto", "SUV", "Van"} or not 1 <= capacity <= 8:
        flash("Select a valid vehicle type and passenger capacity (1–8).", "error")
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 400

    conn = get_db_connection()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT driver_id FROM DRIVER WHERE phone=%s OR license_no=%s", (phone, license_no))
        if cursor.fetchone():
            flash("That phone number or driving licence is already registered.", "error")
            return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 409
        cursor.execute("SELECT vehicle_id FROM VEHICLE WHERE registration_no=%s", (registration_no,))
        if cursor.fetchone():
            flash("That vehicle registration number is already registered.", "error")
            return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 409
    except mysql.connector.Error:
        app.logger.exception("Driver registration duplicate check failed")
        flash("Could not check registration details. Please try again.", "error")
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 500
    finally:
        cursor.close()
        conn.close()

    try:
        provider_id = send_otp(phone)
        challenge_id = create_otp_challenge(phone, name, provider_id)
    except (RuntimeError, requests.RequestException, mysql.connector.Error):
        app.logger.exception("Could not start driver registration OTP")
        flash("Could not send OTP. Check your 2Factor configuration.", "error")
        return render_template_string(DRIVER_REGISTER_TEMPLATE, values=request.form), 502

    session["otp_challenge_id"] = challenge_id
    session["otp_flow"] = "driver_register"
    session["pending_driver_registration"] = {
        "name": name, "phone": phone, "license_no": license_no,
        "registration_no": registration_no, "vehicle_type": vehicle_type,
        "capacity": capacity,
    }
    flash("OTP sent. Verify your phone to finish registration.", "success")
    return redirect(url_for("verify_driver_registration"))

@app.route("/verify-driver-registration", methods=["GET", "POST"])
def verify_driver_registration():
    if session.get("otp_flow") != "driver_register":
        flash("Start driver registration first.", "error")
        return redirect(url_for("driver_register"))
    challenge_id = session.get("otp_challenge_id")
    pending = session.get("pending_driver_registration")
    challenge = get_otp_challenge(challenge_id) if challenge_id else None
    if not pending or not challenge or challenge["consumed_at"]:
        session.pop("pending_driver_registration", None)
        session.pop("otp_challenge_id", None)
        session.pop("otp_flow", None)
        flash("Registration OTP is invalid. Please start again.", "error")
        return redirect(url_for("driver_register"))
    if datetime.now() > challenge["expires_at"]:
        session.pop("pending_driver_registration", None)
        session.pop("otp_challenge_id", None)
        session.pop("otp_flow", None)
        flash("OTP expired. Please register again.", "error")
        return redirect(url_for("driver_register"))
    if request.method == "GET":
        return render_template_string(DRIVER_VERIFY_TEMPLATE, phone=challenge["phone"])
    if challenge["attempts"] >= 5:
        session.pop("pending_driver_registration", None)
        session.pop("otp_challenge_id", None)
        session.pop("otp_flow", None)
        flash("Too many OTP attempts. Please register again.", "error")
        return redirect(url_for("driver_register"))
    try:
        valid = verify_otp(challenge["provider_session_id"], request.form.get("otp", ""))
    except (RuntimeError, requests.RequestException):
        app.logger.exception("Driver registration OTP verification failed")
        flash("OTP service failed. Please try again.", "error")
        return redirect(url_for("verify_driver_registration"))
    if not valid:
        increment_otp_attempts(challenge_id)
        flash("Incorrect OTP. Try again.", "error")
        return redirect(url_for("verify_driver_registration"))
    if not consume_otp_challenge(challenge_id):
        flash("This OTP has already been used. Start again.", "error")
        return redirect(url_for("driver_register"))

    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        conn.start_transaction()
        cursor.execute("SELECT driver_id FROM DRIVER WHERE phone=%s OR license_no=%s FOR UPDATE", (pending["phone"], pending["license_no"]))
        if cursor.fetchone():
            conn.rollback()
            flash("Phone or licence was registered while you were verifying. Contact CampusRide support.", "error")
            return redirect(url_for("driver_register"))
        cursor.execute("SELECT vehicle_id FROM VEHICLE WHERE registration_no=%s FOR UPDATE", (pending["registration_no"],))
        if cursor.fetchone():
            conn.rollback()
            flash("That vehicle registration number is already registered.", "error")
            return redirect(url_for("driver_register"))
        cursor.execute("INSERT INTO DRIVER (name, phone, license_no, status) VALUES (%s, %s, %s, 'INACTIVE')", (pending["name"], pending["phone"], pending["license_no"]))
        driver_id = cursor.lastrowid
        cursor.execute("INSERT INTO VEHICLE (driver_id, registration_no, vehicle_type, capacity) VALUES (%s, %s, %s, %s)", (driver_id, pending["registration_no"], pending["vehicle_type"], pending["capacity"]))
        conn.commit()
    except mysql.connector.Error:
        conn.rollback()
        app.logger.exception("Could not save driver registration")
        flash("Could not save driver registration. Check the terminal and database schema.", "error")
        return redirect(url_for("driver_register"))
    finally:
        cursor.close()
        conn.close()

    session.clear()
    flash("Phone verified. Driver registration submitted for approval. You can log in after your account is activated.", "success")
    return redirect(url_for("driver_login"))

# -------------------- DRIVER DASHBOARD --------------------

@app.route("/driver-dashboard")

@driver_login_required

def driver_dashboard():

    driver = get_current_driver()

    if not driver or driver["status"] == "INACTIVE":

        session.clear()

        flash("Driver account is unavailable.", "error")

        return redirect(url_for("driver_login"))

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        cursor.execute(

            """

            SELECT

                r.ride_id,

                r.rider_id,

                rider.name AS rider_name,

                rider.phone AS rider_phone,

                r.pickup_location,

                r.drop_location,

                r.ride_time,

                r.duration_minutes,

                r.party_size,

                r.fare,

                r.status,

                v.vehicle_type,

                v.registration_no

            FROM RIDE r

            JOIN RIDER rider ON rider.rider_id = r.rider_id

            JOIN VEHICLE v ON v.vehicle_id = r.vehicle_id

            WHERE r.driver_id = %s

              AND r.status IN ('REQUESTED', 'ACCEPTED', 'ONGOING')

            ORDER BY

                CASE r.status

                    WHEN 'REQUESTED' THEN 1

                    WHEN 'ACCEPTED' THEN 2

                    WHEN 'ONGOING' THEN 3

                END,

                r.ride_time ASC

            """,

            (driver["driver_id"],),

        )

        rides = cursor.fetchall()

    finally:

        cursor.close()

        conn.close()

    return render_template(

        "driver_dashboard.html",

        driver=driver,

        rides=rides,

    )

# -------------------- ACCEPT RIDE REQUEST --------------------

@app.route("/driver/accept/<int:ride_id>", methods=["POST"])

@driver_login_required

def accept_ride(ride_id):

    driver_id = session["driver_id"]

    conn = get_db_connection()

    cursor = conn.cursor(dictionary=True)

    try:

        conn.start_transaction()

        # Serialize acceptance attempts for this driver.

        cursor.execute(

            """

            SELECT driver_id, status

            FROM DRIVER

            WHERE driver_id = %s

            FOR UPDATE

            """,

            (driver_id,),

        )

        driver = cursor.fetchone()

        if not driver or driver["status"] == "INACTIVE":

            conn.rollback()

            flash("Driver account is unavailable.", "error")

            return redirect(url_for("driver_dashboard"))

        cursor.execute(

            """

            SELECT ride_id, driver_id, vehicle_id, ride_time,

                   duration_minutes, status

            FROM RIDE

            WHERE ride_id = %s

            FOR UPDATE

            """,

            (ride_id,),

        )

        ride = cursor.fetchone()

        if (

            not ride

            or ride["driver_id"] != driver_id

            or ride["status"] != "REQUESTED"

        ):

            conn.rollback()

            flash("This request is no longer available to accept.", "error")

            return redirect(url_for("driver_dashboard"))

        # Recheck overlapping rides inside the transaction.

        cursor.execute(

            """

            SELECT ride_id

            FROM RIDE

            WHERE driver_id = %s

              AND ride_id <> %s

              AND status IN ('REQUESTED', 'ACCEPTED', 'ONGOING')

              AND ride_time < DATE_ADD(

                    %s, INTERVAL %s MINUTE

                  )

              AND DATE_ADD(

                    ride_time, INTERVAL duration_minutes MINUTE

                  ) > %s

            LIMIT 1

            """,

            (

                driver_id,

                ride_id,

                ride["ride_time"],

                ride["duration_minutes"],

                ride["ride_time"],

            ),

        )

        conflict = cursor.fetchone()

        if conflict:

            conn.rollback()

            flash(

                "Cannot accept: another ride overlaps this time slot.",

                "error",

            )

            return redirect(url_for("driver_dashboard"))

        cursor.execute(

            """

            UPDATE RIDE

            SET status = 'ACCEPTED'

            WHERE ride_id = %s

              AND driver_id = %s

              AND status = 'REQUESTED'

            """,

            (ride_id, driver_id),

        )

        if cursor.rowcount != 1:

            conn.rollback()

            flash("Request changed. Refresh and try again.", "error")

            return redirect(url_for("driver_dashboard"))

        conn.commit()

        flash(f"Ride #{ride_id} accepted successfully!", "success")

    except mysql.connector.Error:

        conn.rollback()

        app.logger.exception("Driver acceptance failed")

        flash("Could not accept the ride. Check the terminal.", "error")

    finally:

        cursor.close()

        conn.close()

    return redirect(url_for("driver_dashboard"))

# -------------------- REJECT RIDE REQUEST --------------------

@app.route("/driver/reject/<int:ride_id>", methods=["POST"])

@driver_login_required

def reject_ride(ride_id):

    driver_id = session["driver_id"]

    conn = get_db_connection()

    cursor = conn.cursor()

    try:

        cursor.execute(

            """

            UPDATE RIDE

            SET status = 'CANCELLED'

            WHERE ride_id = %s

              AND driver_id = %s

              AND status = 'REQUESTED'

            """,

            (ride_id, driver_id),

        )

        conn.commit()

        if cursor.rowcount == 1:

            flash(f"Ride #{ride_id} rejected.", "success")

        else:

            flash("Request not found or it has already changed.", "error")

    except mysql.connector.Error:

        conn.rollback()

        app.logger.exception("Driver rejection failed")

        flash("Could not reject the request.", "error")

    finally:

        cursor.close()

        conn.close()

    return redirect(url_for("driver_dashboard"))

# -------------------- START RIDE --------------------

@app.route("/driver/start/<int:ride_id>", methods=["POST"])
@driver_login_required
def start_ride(ride_id):
    driver_id = session["driver_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE RIDE
            SET status = 'ONGOING'
            WHERE ride_id = %s
              AND driver_id = %s
              AND status = 'ACCEPTED'
            """,
            (ride_id, driver_id),
        )
        conn.commit()
        if cursor.rowcount == 1:
            flash(f"Ride #{ride_id} started.", "success")
        else:
            flash("Only your accepted rides can be started.", "error")
    except mysql.connector.Error:
        conn.rollback()
        app.logger.exception("Could not start ride")
        flash("Could not start the ride.", "error")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("driver_dashboard"))


# -------------------- COMPLETE RIDE --------------------

@app.route("/driver/complete/<int:ride_id>", methods=["POST"])
@driver_login_required
def complete_ride(ride_id):
    driver_id = session["driver_id"]
    conn = get_db_connection()
    cursor = conn.cursor()
    try:
        cursor.execute(
            """
            UPDATE RIDE
            SET status = 'COMPLETED'
            WHERE ride_id = %s
              AND driver_id = %s
              AND status = 'ONGOING'
            """,
            (ride_id, driver_id),
        )
        conn.commit()
        if cursor.rowcount == 1:
            flash(f"Ride #{ride_id} completed.", "success")
        else:
            flash("Only your ongoing rides can be completed.", "error")
    except mysql.connector.Error:
        conn.rollback()
        app.logger.exception("Could not complete ride")
        flash("Could not complete the ride.", "error")
    finally:
        cursor.close()
        conn.close()
    return redirect(url_for("driver_dashboard"))


# -------------------- DRIVER LOGOUT --------------------

@app.route("/driver-logout", methods=["POST"])

@driver_login_required

def driver_logout():

    session.clear()

    flash("Driver logged out.", "success")

    return redirect(url_for("driver_login"))

# ==================================================

# RUN

# ==================================================

if __name__ == "__main__":

    # Local development only; do not expose this server publicly.

    app.run(host="127.0.0.1", port=5000, debug=False)
