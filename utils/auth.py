import streamlit as st

# Dummy credentials (you can expand to use a database or hashed login)
USERS = {
    "admin": "admin123",
    "analyst": "malvista2025"
}

def login():
    st.sidebar.header("🔐 Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")
    login_button = st.sidebar.button("Login")

    if login_button:
        if USERS.get(username) == password:
            st.session_state["authenticated"] = True
            st.sidebar.success("✅ Login successful")
            return True
        else:
            st.sidebar.error("❌ Invalid credentials")

    return st.session_state.get("authenticated", False)

def logout():
    if st.sidebar.button("Logout"):
        st.session_state["authenticated"] = False
        st.experimental_rerun()
