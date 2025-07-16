import streamlit as st

# Dummy credentials
USERS = {
    "admin": "admin123",
    "analyst": "malvista2025"
}

def login():
    st.sidebar.header("🔐 Login")

    # Initialize authentication state
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        username = st.sidebar.text_input("Username")
        password = st.sidebar.text_input("Password", type="password")
        login_button = st.sidebar.button("Login")

        if login_button:
            if USERS.get(username) == password:
                st.session_state["authenticated"] = True
                st.sidebar.success("✅ Login successful")
            else:
                st.sidebar.error("❌ Invalid credentials")

    return st.session_state["authenticated"]

def logout():
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.experimental_rerun()
