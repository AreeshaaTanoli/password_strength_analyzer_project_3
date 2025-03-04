import streamlit as st
import re
import math
import hashlib
import requests
import pandas as pd

# Initialize Streamlit config FIRST
st.set_page_config(
    page_title="Password Strength Analyzer",
    page_icon="🔒",
    layout="centered"
)

# ---------------------------
# Security Functions
# ---------------------------

def check_hibp_breach(password: str) -> bool:
    """Check if password exists in breaches"""
    sha1_hash = hashlib.sha1(password.encode()).hexdigest().upper()
    prefix, suffix = sha1_hash[:5], sha1_hash[5:]
    response = requests.get(
        f"https://api.pwnedpasswords.com/range/{prefix}",
        headers={"User-Agent": "SecurityTool"}
    )
    return any(line.split(':')[0] == suffix for line in response.text.splitlines())

def calculate_entropy(password: str) -> float:
    """Calculate password strength in bits"""
    charset = 0
    if re.search(r'[a-z]', password): charset += 26
    if re.search(r'[A-Z]', password): charset += 26
    if re.search(r'\d', password): charset += 10
    if re.search(r'[!@#$%^&*]', password): charset += 10
    return len(password) * math.log2(charset) if charset else 0

# ---------------------------
# CSS Animations
# ---------------------------

st.markdown("""
<style>
@keyframes slideIn {
    from { transform: translateX(-50px); opacity: 0; }
    to { transform: translateX(0); opacity: 1; }
}

.header {
    animation: slideIn 0.8s ease-out;
}
</style>
""", unsafe_allow_html=True)

# ---------------------------
# Main App Interface (Corrected)
# ---------------------------

# Header Section (FIXED)
st.markdown('<div class="header">', unsafe_allow_html=True)
st.title("🔐 Password Strength Analyzer")
st.markdown("---")
st.markdown('</div>', unsafe_allow_html=True)  # ✅ Correct parameter

password = st.text_input("Enter Password:", type="password")

if st.button("Analyze"):
    if password:
        with st.spinner("Analyzing..."):
            is_breached = check_hibp_breach(password)
            entropy = calculate_entropy(password)
            
            # Results
            col1, col2 = st.columns(2)
            with col1:
                st.metric("Entropy Score", f"{entropy:.1f} bits")
                st.metric("Breach Status", 
                         "⚠️ Compromised" if is_breached else "✅ Secure")
            
            # Strength Meter
            progress = min(entropy / 100, 1.0)
            st.progress(progress)
            
            # Recommendations
            if entropy < 30:
                st.error("Weak Password - Needs urgent improvement!")
            elif entropy < 60:
                st.warning("Moderate Strength - Could be better")
            else:
                st.success("Strong Password - Good job!")

st.markdown("---")
st.caption("Developed by Areesha Tanoli | 2025")