import streamlit as st

USERS = {
    "admin": "admin123",
    "analyst": "malvista2025"
}

def login():
    if "authenticated" not in st.session_state:
        st.session_state["authenticated"] = False

    if not st.session_state["authenticated"]:
        with st.sidebar:
            st.header("🔐 Login")
            username = st.text_input("Username", key="username_input")
            password = st.text_input("Password", type="password", key="password_input")
            if st.button("Login", key="login_button"):
                if USERS.get(username) == password:
                    st.session_state["authenticated"] = True
                    st.success("✅ Login successful")
                    st.experimental_rerun()
                else:
                    st.error("❌ Invalid credentials")
    return st.session_state["authenticated"]

def logout():
    if st.sidebar.button("Logout", key="logout_button"):
        st.session_state["authenticated"] = False
        st.experimental_rerun()
