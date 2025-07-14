# utils/auth.py

import streamlit as st

# Dummy user database (replace with secure store or hash later)
USERS = {
    "admin": "admin123",
    "analyst": "securepass"
}

def login():
    st.title("🔐 Login to MalVista")

    if "authenticated" not in st.session_state:
        st.session_state.authenticated = False

    username = st.text_input("Username")
    password = st.text_input("Password", type="password")

    if st.button("Login"):
        if username in USERS and USERS[username] == password:
            st.session_state.authenticated = True
            st.success("✅ Logged in successfully")
        else:
            st.error("❌ Invalid username or password")

    return st.session_state.authenticated

def logout():
    if st.button("Logout"):
        st.session_state.authenticated = False
        st.experimental_rerun()
