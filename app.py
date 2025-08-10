import streamlit as st
import joblib
import requests
import pyodbc
import re
import bcrypt
import uuid
from bs4 import BeautifulSoup

# ================== Database Setup ==================
conn = pyodbc.connect(
    'DRIVER={SQL Server};'
    'SERVER=WALEED;'
    'DATABASE=NewsAppDB;'
    'Trusted_Connection=yes;'
)
cursor = conn.cursor()

# ================== Constants ==================
ADMIN_EMAIL = "admin@example.com"
ADMIN_PASSWORD = "admin123"
ADMIN_TOKEN = "admin_secret_token"  # Hardcoded token for admin
MIN_TEXT_LENGTH = 50

# ================== Session Restoration ==================
token_param = st.query_params.get("token", None)

if token_param and not st.session_state.get("logged_in"):
    if token_param == ADMIN_TOKEN:
        st.session_state.update({
            "logged_in": True,
            "is_admin": True,
            "user_name": "Admin User",
            "user_role": "Admin"
        })
    else:
        cursor.execute("SELECT * FROM Users WHERE SessionToken = ?", (token_param,))
        user = cursor.fetchone()
        if user:
            st.session_state.update({
                "logged_in": True,
                "user_name": user.Name,
                "user_age": user.Age,
                "user_email": user.Email,
                "user_role": "Member"
            })
            st.query_params["token"] = token_param

# ================== Session State Setup ==================
session_defaults = {
    "current_page": "home",
    "logged_in": False,
    "is_admin": False,
    "show_dropdown": False,
    "user_name": "",
    "user_email": "",
    "user_age": 18,
    "user_role": "Member"
}

for key, value in session_defaults.items():
    if key not in st.session_state:
        st.session_state[key] = value

# ================== Core Functions ==================
def set_page(page_name):
    st.session_state.current_page = page_name
    st.session_state.show_dropdown = False

def hash_password(password):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt())

def check_password(hashed_pw, user_pw):
    return bcrypt.checkpw(user_pw.encode('utf-8'), hashed_pw)

# ================== Page Displays ==================
def show_main_page():
    st.write("## Analyze News Content")
    
    try:
        vectorizer = joblib.load("vectorizer.jb")
        model = joblib.load("lr_model.jb")
    except Exception as e:
        st.error(f"Model loading error: {str(e)}")
        return

    # --------- NEW FUNCTIONALITY FROM appp.py ---------
    # Session state for text input
    if 'news_text' not in st.session_state:
        st.session_state.news_text = ""
    def update_text():
        st.session_state.news_text = st.session_state.text_area_content

    input_text = st.text_area(
        "Paste news article text:",
        height=150,
        key="text_area_content",
        value=st.session_state.news_text,
        on_change=update_text
    )
    input_url = st.text_input("Or enter article URL:")

    # Calculate and display word count from session state
    word_count = len(st.session_state.news_text.split()) if st.session_state.news_text else 0
    word_count_display = st.empty()
    word_count_display.caption(f"Word count: {word_count}")

    # Show warning if word count is below minimum for text
    if st.session_state.news_text and word_count < MIN_TEXT_LENGTH:
        st.warning(f"Minimum {MIN_TEXT_LENGTH} words required (currently {word_count})")
    else:
        st.empty()  # Clear any existing warnings if conditions aren't met

    if st.button("Analyze Content"):
        # Don't allow both fields at once
        if st.session_state.news_text.strip() and input_url.strip():
            st.warning("Please provide either text OR URL, not both")
            return

        if st.session_state.news_text.strip():
            content = st.session_state.news_text
            word_count = len(content.split())
            if word_count < MIN_TEXT_LENGTH:
                # Already shown warning above, just return
                return
        elif input_url.strip():
            try:
                response = requests.get(input_url, timeout=10)
                soup = BeautifulSoup(response.content, 'html.parser')
                content = ' '.join([p.get_text() for p in soup.find_all('p')])
                word_count = len(content.split())
                if word_count < MIN_TEXT_LENGTH:
                    st.warning(f"Minimum {MIN_TEXT_LENGTH} words required (currently {word_count})")
                    return
            except Exception as e:
                st.error(f"URL processing error: {str(e)}")
                return
        else:
            st.warning("Please provide either text or URL")
            return

        try:
            transformed = vectorizer.transform([content])
            prediction = model.predict(transformed)[0]
            proba = model.predict_proba(transformed)[0][prediction] * 100
            result = "Real News" if prediction == 1 else "Fake News"
            st.success(f"**Analysis Result**: {result} (Confidence: {proba:.1f}%)")
        except Exception as e:
            st.error(f"Analysis failed: {str(e)}")
    # ---------------------------------------------------

def show_login_page():
    st.title("User Login")
    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")

    if st.button("Sign In"):
        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            st.error("Invalid email format")
            return

        if email == ADMIN_EMAIL and password == ADMIN_PASSWORD:
            st.session_state.update({
                "logged_in": True,
                "is_admin": True,
                "user_name": "Admin User",
                "user_role": "Admin"
            })
            st.query_params["token"] = ADMIN_TOKEN
            set_page("home")
            st.rerun()
        else:
            try:
                cursor.execute("SELECT * FROM Users WHERE Email = ?", (email,))
                user = cursor.fetchone()
                if user and check_password(user.Password, password):
                    token = str(uuid.uuid4())
                    cursor.execute("UPDATE Users SET SessionToken = ? WHERE Email = ?", (token, email))
                    conn.commit()
                    st.session_state.update({
                        "logged_in": True,
                        "user_name": user.Name,
                        "user_age": user.Age,
                        "user_email": user.Email,
                        "user_role": "Member"
                    })
                    st.query_params["token"] = token
                    set_page("home")
                    st.rerun()
                else:
                    st.error("Invalid credentials")
            except Exception as e:
                st.error(f"Login error: {str(e)}")

def show_signup_page():
    st.title("Create Account")
    name = st.text_input("Full Name")
    age = st.number_input("Age", min_value=1, max_value=100, value=18)
    email = st.text_input("Email Address")
    password = st.text_input("Password", type="password")

    if st.button("Register Account"):
        if not all([name, email, password]):
            st.error("All fields are required")
            return

        if not re.match(r'^[\w\.-]+@[\w\.-]+\.\w+$', email):
            st.error("Invalid email format")
            return

        try:
            hashed_pw = hash_password(password)
            cursor.execute("INSERT INTO Users (Name, Age, Email, Password) VALUES (?, ?, ?, ?)", 
                         (name, age, email, hashed_pw))
            conn.commit()
            st.success("Account created! Please login")
            set_page("login")
        except pyodbc.IntegrityError:
            st.error("Email already registered")
        except Exception as e:
            st.error(f"Registration error: {str(e)}")

def show_profile_settings():
    st.title("Profile Settings")
    
    new_name = st.text_input("Name", value=st.session_state.user_name)
    new_age = st.number_input("Age", 
                            min_value=1, 
                            max_value=100, 
                            value=st.session_state.user_age)

    if st.button("Update Profile"):
        try:
            cursor.execute("""
                UPDATE Users 
                SET Name = ?, Age = ?
                WHERE Email = ?
            """, (new_name, new_age, st.session_state.user_email))
            conn.commit()
            st.session_state.user_name = new_name
            st.session_state.user_age = new_age
            st.success("Profile updated successfully!")
        except Exception as e:
            st.error(f"Update failed: {str(e)}")

def show_account_settings():
    st.title("Account Settings")
    
    current_pw = st.text_input("Current Password", type="password")
    new_pw = st.text_input("New Password", type="password")
    confirm_pw = st.text_input("Confirm New Password", type="password")

    if st.button("Change Password"):
        if not (current_pw and new_pw and confirm_pw):
            st.error("All fields are required")
            return
        
        if new_pw != confirm_pw:
            st.error("New passwords don't match")
            return

        try:
            cursor.execute("SELECT Password FROM Users WHERE Email = ?", 
                         (st.session_state.user_email,))
            db_pw = cursor.fetchone()[0]
            
            if check_password(db_pw, current_pw):
                new_hashed_pw = hash_password(new_pw)
                cursor.execute("""
                    UPDATE Users 
                    SET Password = ?
                    WHERE Email = ?
                """, (new_hashed_pw, st.session_state.user_email))
                conn.commit()
                st.success("Password updated successfully!")
            else:
                st.error("Incorrect current password")
        except Exception as e:
            st.error(f"Password change failed: {str(e)}")

def show_admin_panel():
    st.title("Administration Dashboard")
    cursor.execute("SELECT UserID, Name, Age, Email FROM Users")
    users = cursor.fetchall()

    if users:
        for user in users:
            cols = st.columns([4, 1])
            cols[0].write(f"**{user.Name}** (Age: {user.Age}, Email: {user.Email})")
            if cols[1].button(f"Delete {user.Name}", key=f"del_{user.UserID}"):
                cursor.execute("DELETE FROM Users WHERE UserID = ?", (user.UserID,))
                conn.commit()
                st.rerun()
    else:
        st.write("No registered users")

# ================== UI Components ==================
def profile_dropdown():
    st.markdown("""
    <style>
    .dropdown-box {
        position: absolute;
        right: 20px;
        
        padding: 15px;
        border-radius: 8px;
        box-shadow: 0 2px 8px rgba(0,0,0,0.1);
        z-index: 1000;
        min-width: 200px;
    }
    </style>
    """, unsafe_allow_html=True)

    if st.session_state.show_dropdown:
        with st.container():
            st.markdown('<div class="dropdown-box">', unsafe_allow_html=True)
            st.write(f"👤 **{st.session_state.user_name}**")
            st.write(f"_{st.session_state.user_role}_")
            st.markdown("---")
            
            if not st.session_state.is_admin:
                if st.button("🛠 Profile Settings"):
                    set_page("profile_settings")
                
                if st.button("⚙ Account Settings"):
                    set_page("account_settings")
            
            if st.button("🔒 Logout"):
                if st.session_state.is_admin:
                    st.query_params.clear()
                else:
                    cursor.execute("UPDATE Users SET SessionToken = NULL WHERE Email = ?", 
                                 (st.session_state.user_email,))
                    conn.commit()
                    st.query_params.clear()
                st.session_state.update({
                    "logged_in": False,
                    "is_admin": False,
                    "user_name": "",
                    "user_email": "",
                    "user_age": 18,
                    "user_role": "Member"
                })
                set_page("home")
                st.rerun()
            
            st.markdown('</div>', unsafe_allow_html=True)

def navbar():
    cols = st.columns([1, 1, 1, 1])
    
    with cols[0]:
        if st.button("🏠 Home"):
            set_page("home")
    
    with cols[2]:
        if st.session_state.logged_in:
            if st.button("👤 Profile"):
                st.session_state.show_dropdown = not st.session_state.show_dropdown
            profile_dropdown()
        else:
            if st.button("🔑 Login"):
                set_page("login")
    
    with cols[3]:
        if not st.session_state.logged_in:
            if st.button("📝 Signup"):
                set_page("signup")
        elif st.session_state.is_admin:
            if st.button("Admin Panel"):
                set_page("admin_panel")

# ================== Main Application ==================
navbar()

if st.session_state.current_page == "home":
    show_main_page()
elif st.session_state.current_page == "login":
    show_login_page()
elif st.session_state.current_page == "signup":
    show_signup_page()
elif st.session_state.current_page == "profile_settings":
    show_profile_settings()
elif st.session_state.current_page == "account_settings":
    show_account_settings()
elif st.session_state.current_page == "admin_panel":
    if st.session_state.is_admin:
        show_admin_panel()
    else:
        st.error("Admin access required")
        set_page("home")

conn.close()