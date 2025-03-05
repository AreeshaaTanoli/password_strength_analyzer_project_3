import streamlit as st
import re
import math
import hashlib
import requests
import random
import string

# Initialize Streamlit config FIRST
st.set_page_config(
    page_title="Pro Password Manager",
    page_icon="🔒",
    layout="centered"
)

# ---------------------------
# Core Security Functions
# ---------------------------

def check_hibp_breach(password: str) -> bool:
    """Check password against HIBP breach database"""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "EnterpriseScanner"}
    )
    return any(line.split(':')[0] == suffix for line in response.text.splitlines())

def calculate_entropy(password: str) -> float:
    """Calculate password complexity in bits"""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[!@#$%^&*]', password): charset += 10
    return len(password) * math.log2(charset) if charset else 0

def generate_strong_password(length=12):
    """Generate cryptographically secure password"""
    chars = string.ascii_letters + string.digits + "!@#$%^&*"
    while True:
        password = ''.join(random.SystemRandom().choice(chars) for _ in range(length))
        if all([re.search(r'[A-Z]', password),
                re.search(r'[a-z]', password),
                re.search(r'\d', password),
                re.search(r'[!@#$%^&*]', password)]):
            return password

# ---------------------------
# Professional Interface
# ---------------------------

def main():
    # Custom CSS for animations and buttons
    st.markdown("""
    <style>
    @keyframes gradient {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    .generate-btn {
        background: linear-gradient(45deg, #4CAF50, #8BC34A);
        color: white !important;
        border: none;
        border-radius: 25px;
        padding: 10px 25px;
        transition: transform 0.3s ease;
    }
    
    .generate-btn:hover {
        transform: scale(1.05);
        box-shadow: 0 5px 15px rgba(76,175,80,0.3);
    }
    
    .analyze-btn {
        background: linear-gradient(45deg, #2196F3, #03A9F4);
        color: white !important;
        border: none;
        border-radius: 25px;
        padding: 10px 30px;
        animation: gradient 3s ease infinite;
        border: 2px solid #ffffff30;
    }
    
    .analyze-btn:hover {
        transform: scale(1.02);
        box-shadow: 0 5px 15px rgba(33,150,243,0.3);
    }
    
    .button-container {
        display: flex;
        gap: 1rem;
        justify-content: center;
        margin: 2rem 0;
    }
    </style>
    """, unsafe_allow_html=True)

    st.title("🔐 Enterprise Password Toolkit")
    st.markdown("---")

    # Session State Management
    if 'current_pass' not in st.session_state:
        st.session_state.current_pass = ""
    if 'analyze_flag' not in st.session_state:
        st.session_state.analyze_flag = False

    # Input Section with Styled Generate Button
    with st.container():
        col1, col2 = st.columns([4, 1])
        with col1:
            user_input = st.text_input(
                "Enter/Generate Password:", 
                value=st.session_state.current_pass,
                type="password",
                key="pass_input",
                placeholder="🔒 Type or generate password"
            )
        with col2:
            st.markdown("<div style='height:28px'></div>", unsafe_allow_html=True)
            if st.button("🔑 Generate", 
                        key="generate_btn",
                        help="Generate military-grade password",
                        type="secondary"):
                st.session_state.current_pass = generate_strong_password()
                st.session_state.analyze_flag = True
                st.rerun()

    # Centered Analyze Button with Animation
    st.markdown('<div class="button-container">', unsafe_allow_html=True)
    analyze_clicked = st.button("🚀 Analyze Password", 
                               key="analyze_btn",
                               type="primary")
    st.markdown('</div>', unsafe_allow_html=True)

    # Analysis Logic
    if analyze_clicked or st.session_state.analyze_flag:
        if st.session_state.pass_input:
            with st.spinner("🔍 Scanning password security..."):
                password = st.session_state.pass_input
                is_breached = check_hibp_breach(password)
                entropy = calculate_entropy(password)
                
                # Security Report
                st.markdown("---")
                st.subheader("Security Intelligence Report")
                
                # Metrics Cards
                col1, col2, col3 = st.columns(3)
                with col1:
                    with st.container(border=True):
                        st.metric("Entropy Score", f"{entropy:.1f} bits", 
                                 help="80+ bits recommended")
                        st.progress(min(entropy/100, 1.0))
                with col2:
                    with st.container(border=True):
                        st.metric("Breach Status", 
                                 "⚠️ Compromised" if is_breached else "✅ Secure",
                                 delta="Critical" if is_breached else "Safe",
                                 delta_color="inverse")
                with col3:
                    risk_level = "High Risk" if entropy < 60 else "Low Risk"
                    st.metric("Risk Level", risk_level)

                # Recommendations
                with st.expander("📌 Security Recommendations", expanded=True):
                    if is_breached:
                        st.error("""
                        **Immediate Action Required**  
                        - Change password immediately  
                        - Enable 2FA  
                        - Check account activity
                        """)
                    if entropy < 60:
                        st.warning("""
                        **Improvement Needed**  
                        - Use 16+ characters  
                        - Add symbols (!@#$%)  
                        - Avoid dictionary words
                        """)
                    else:
                        st.success("""
                        **Best Practices**  
                        - Regular password rotation  
                        - Use password manager  
                        - Unique passwords per account
                        """)

    st.markdown("---")
    st.caption("© 2025 CyberSecurity Pro | Developed by Areesha Tanoli")

if __name__ == "__main__":
    main()