import streamlit as st

# Dummy user database
USERS = {
    "admin": "admin123",
    "analyst": "malvista2025"
}

def login():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    st.sidebar.header("🔐 Login")
    username = st.sidebar.text_input("Username", key="login_user")
    password = st.sidebar.text_input("Password", type="password", key="login_pass")
    login_button = st.sidebar.button("Login")

    if login_button:
        if USERS.get(username) == password:
            st.session_state["authenticated"] = True
            st.success("✅ Login successful")
        else:
            st.session_state["authenticated"] = False
            st.error("❌ Invalid credentials")

    return st.session_state["authenticated"]

def logout():
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.sidebar.success("👋 Logged out")
        st.experimental_rerun()
