import streamlit as st

VALID_USERS = {
    "admin": "admin123",
    "analyst": "malvista2024"
}

def login():
    st.sidebar.subheader("🔐 Login")
    username = st.sidebar.text_input("Username")
    password = st.sidebar.text_input("Password", type="password")

    if st.sidebar.button("Login"):
        if username in VALID_USERS and VALID_USERS[username] == password:
            st.session_state["authenticated"] = True
            st.session_state["user"] = username
            st.success(f"✅ Welcome, {username}!")
        else:
            st.error("❌ Invalid username or password.")

def is_authenticated():
    return st.session_state.get("authenticated", False)

def logout():
    if st.sidebar.button("Logout"):
        st.session_state.clear()
        st.experimental_rerun()
