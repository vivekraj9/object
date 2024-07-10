import streamlit as st
import sqlite3
import hashlib
import re
import cv2
import torch
from ultralytics import YOLO
import numpy as np
from PIL import Image

# Function to create a connection to the SQLite database
def create_connection():
    conn = sqlite3.connect('users.db')
    return conn

# Function to create the users table if it doesn't exist
def create_table(conn):
    conn.execute('''CREATE TABLE IF NOT EXISTS users
             (username TEXT PRIMARY KEY,
             password TEXT NOT NULL,
             email TEXT NOT NULL)''')

# Function to insert a new user into the database
def insert_user(conn, username, password, email):
    conn.execute("INSERT INTO users (username, password, email) VALUES (?, ?, ?)", (username, password, email))
    conn.commit()

# Function to retrieve a user by username from the database
def get_user(conn, username):
    cursor = conn.execute("SELECT * FROM users WHERE username=?", (username,))
    return cursor.fetchone()

# Function to update a user's password in the database
def update_password(conn, username, new_password):
    conn.execute("UPDATE users SET password=? WHERE username=?", (new_password, username))
    conn.commit()

# Function to hash a password
def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

# Function to verify a password
def verify_password(hashed_password, password):
    return hashed_password == hashlib.sha256(password.encode()).hexdigest()

# Function to validate username
def validate_username(username):
    return re.match(r"^[a-zA-Z0-9_]{3,15}$", username)

# Function to validate email
def validate_email(email):
    return re.match(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$", email)

# Function to validate password
def validate_password(password):
    return re.match(r"^(?=.*[A-Z])(?=.*[a-z])(?=.*\d)(?=.*[@$!%*?&#])[A-Za-z\d@$!%*?&#]{8,}$", password)

def login(conn):
    st.title("Login Page")
    username = st.text_input("Username")
    password = st.text_input("Password", type="password")
    if st.button("Login", key="login_button"):
        user = get_user(conn, username)
        if user and verify_password(user[1], password):
            st.success("Logged in successfully")
            st.session_state.logged_in = True
            st.session_state.username = username
            st.rerun()  # Rerun the app to refresh the state
        else:
            st.error("Invalid username or password")

def signup(conn):
    st.title("Signup Page")
    new_username = st.text_input("New Username")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    email = st.text_input("Email")
    if st.button("Signup", key="signup_button"):
        if get_user(conn, new_username):
            st.error("Username already exists. Please choose a different username.")
        elif not validate_username(new_username):
            st.error("Username must be 3-15 characters long and can contain letters, numbers, and underscores.")
        elif not validate_email(email):
            st.error("Invalid email format.")
        elif not validate_password(new_password):
            st.error("Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.")
        elif new_password != confirm_password:
            st.error("Passwords do not match.")
        else:
            hashed_password = hash_password(new_password)
            insert_user(conn, new_username, hashed_password, email)
            st.success("Signup successful")

def forgot_password(conn):
    st.title("Forgot Password Page")
    username = st.text_input("Username")
    email = st.text_input("Email")
    new_password = st.text_input("New Password", type="password")
    confirm_password = st.text_input("Confirm Password", type="password")
    if st.button("Reset Password", key="reset_password_button"):
        user = get_user(conn, username)
        if user and user[2] == email:
            if not validate_password(new_password):
                st.error("Password must be at least 8 characters long and contain an uppercase letter, a lowercase letter, a number, and a special character.")
            elif new_password != confirm_password:
                st.error("Passwords do not match.")
            else:
                hashed_password = hash_password(new_password)
                update_password(conn, username, hashed_password)
                st.success("Password reset successful")
        else:
            st.error("Invalid username or email")

def detect_heads(results):
    head_count = sum(1 for result in results for box in result.boxes if box.cls == "head")
    return head_count

def object_detection_app():
    # Load the YOLOv8 model
    model = YOLO('best1.pt')

    st.title('YOLOv8 Object Detection App')
    st.write("Upload an image or use the webcam for object detection.")

    # Sidebar options
    option = st.sidebar.selectbox("Select Input Source", ("Image Upload", "Webcam"))

    # Image upload
    if option == "Image Upload":
        uploaded_file = st.file_uploader("Choose an image...", type=["jpg", "jpeg", "png"])

        if uploaded_file is not None:
            # Convert the file to an OpenCV image
            file_bytes = np.asarray(bytearray(uploaded_file.read()), dtype=np.uint8)
            image = cv2.imdecode(file_bytes, 1)
            
            # Slider for confidence threshold
            threshold = st.slider('Confidence Threshold', 0.0, 1.0, 0.5)
            
            # Perform object detection
            results = model.predict(source=image, imgsz=640, conf=threshold)
            
            # Draw boxes on the image
            result_image = results[0].plot()
            
            # Convert the image back to PIL format for display
            st.image(result_image, caption='Processed Image.', use_column_width=True)
            
            # Detect and display the number of people
            # head_count = detect_heads(results)
            # st.write(f"Number of people detected: {head_count}")

    # Webcam input
    elif option == "Webcam":
        run_webcam = st.checkbox('Run Webcam')
        camera = cv2.VideoCapture(0)

        if run_webcam:
            stframe = st.empty()
            
            while run_webcam:
                ret, frame = camera.read()
                if not ret:
                    break

                # Perform object detection
                results = model.predict(source=frame, imgsz=640)
                
                # Draw boxes on the image
                result_frame = results[0].plot()

                # Display the resulting frame
                stframe.image(result_frame, channels="BGR", use_column_width=True)

                # Detect and display the number of people
                # head_count = detect_heads(results)
                # st.write(f"Number of people detected: {head_count}")
        else:
            camera.release()

def main():
    conn = create_connection()
    create_table(conn)

    # Initialize session state if it does not exist
    if 'logged_in' not in st.session_state:
        st.session_state.logged_in = False

    if st.session_state.logged_in:
        st.sidebar.title(f"Welcome, {st.session_state.username}!")
        st.sidebar.button("Logout", on_click=lambda: st.session_state.update({"logged_in": False, "username": ""}))
        page = st.sidebar.selectbox("Choose a page", ["Home", "Object Detection"])
        
        if page == "Home":
            st.title("Home Page")
            st.write("Welcome to our Object Detection Website")
            st.write("You are now logged in.")
        elif page == "Object Detection":
            object_detection_app()
    else:
        st.sidebar.title("Navigation")
        if st.sidebar.button("Login", key="nav_login"):
            st.session_state.page = "Login"
        if st.sidebar.button("Signup", key="nav_signup"):
            st.session_state.page = "Signup"
        if st.sidebar.button("Forgot Password", key="nav_forgot_password"):
            st.session_state.page = "Forgot Password"

        # Determine which page to show
        if 'page' not in st.session_state:
            st.session_state.page = "Login"

        if st.session_state.page == "Login":
            login(conn)
        elif st.session_state.page == "Signup":
            signup(conn)
        elif st.session_state.page == "Forgot Password":
            forgot_password(conn)

if __name__ == "__main__":
    main()
