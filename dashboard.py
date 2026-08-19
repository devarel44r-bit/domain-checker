
import socket
import requests
import streamlit as st

st.set_page_config(
    page_title="Domain Checker",
    page_icon="🌐",
    layout="centered"
)

st.title("🌐 DOMAIN CHECKER")
st.write("Masukkan domain yang ingin diperiksa.")

domain = st.text_input(
    "Domain",
    placeholder="contoh: google.com"
)

if st.button("CHECK DOMAIN"):

    if not domain:
        st.warning("Masukkan domain terlebih dahulu.")

    else:
        domain = domain.strip()
        domain = domain.replace("https://", "")
        domain = domain.replace("http://", "")
        domain = domain.split("/")[0]

        st.divider()
        st.subheader(domain)

        # CEK DNS
        try:
            ip = socket.gethostbyname(domain)
            st.success("✅ DNS AKTIF")
            st.write(f"IP Address: `{ip}`")

        except socket.gaierror:
            st.error("❌ DNS TIDAK DITEMUKAN")

        # CEK HTTP
        try:
            http = requests.get(
                f"http://{domain}",
                timeout=10,
                allow_redirects=True
            )

            st.write("### HTTP")
            st.write(f"Status: **{http.status_code}**")
            st.write(f"Final URL: `{http.url}`")

        except requests.RequestException as error:
            st.error(f"HTTP gagal: {error}")

        # CEK HTTPS
        try:
            https = requests.get(
                f"https://{domain}",
                timeout=10,
                allow_redirects=True
            )

            st.write("### HTTPS")
            st.write(f"Status: **{https.status_code}**")
            st.write(f"Final URL: `{https.url}`")

            if https.status_code == 200:
                st.success("🟢 WEBSITE ONLINE")
            else:
                st.warning(
                    f"Website merespons dengan status {https.status_code}"
                )

        except requests.RequestException as error:
            st.error(f"HTTPS gagal: {error}")