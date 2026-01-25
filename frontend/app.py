"""
Cloud Architecture Review Agent - Streamlit Frontend
"""
import streamlit as st
import requests
import os
from dotenv import load_dotenv

load_dotenv()

# Config
API_URL = os.getenv("API_URL", "http://localhost:8000")

st.set_page_config(
    page_title="Cloud Architecture Review",
    page_icon="☁️",
    layout="wide"
)

st.title("☁️ Cloud Architecture Review Agent")
st.markdown("Upload your Terraform files and get instant security, cost, and best practice feedback.")

st.divider()

# Sidebar
with st.sidebar:
    st.header("About")
    st.markdown("""
    This tool analyzes your Terraform configurations for:
    - 🔴 **Security risks**
    - 💰 **Cost inefficiencies**
    - 📋 **Best practice violations**
    - 🛡️ **Reliability issues**
    """)

    st.divider()

    st.header("Supported Files")
    st.markdown("""
    - `.tf` - Terraform configs
    - `.tf.json` - JSON format
    """)

# Main content
col1, col2 = st.columns([1, 1])

with col1:
    st.header("Upload Terraform")

    uploaded_file = st.file_uploader(
        "Choose a .tf file",
        type=['tf'],
        help="Upload your Terraform configuration file"
    )

    st.markdown("**Or paste your Terraform code:**")

    terraform_text = st.text_area(
        "Terraform Config",
        height=300,
        placeholder="""# Paste your Terraform here...
resource "aws_instance" "example" {
  ami           = "ami-12345678"
  instance_type = "t2.micro"
}
"""
    )

    analyze_button = st.button("🔍 Analyze", type="primary", use_container_width=True)

with col2:
    st.header("Review Results")

    if analyze_button:
        content = None
        filename = "pasted_config.tf"

        if uploaded_file is not None:
            content = uploaded_file.read()
            filename = uploaded_file.name
        elif terraform_text.strip():
            content = terraform_text.encode('utf-8')

        if content:
            with st.spinner("Analyzing your infrastructure..."):
                try:
                    # Use file upload endpoint
                    files = {"file": (filename, content, "text/plain")}
                    response = requests.post(f"{API_URL}/review", files=files)

                    if response.status_code == 200:
                        result = response.json()

                        st.success(f"✅ Analyzed {result['lines_analyzed']} lines from `{result['filename']}`")
                        st.divider()
                        st.markdown(result['review'])

                        # Download button
                        st.download_button(
                            label="📥 Download Report",
                            data=result['review'],
                            file_name=f"review_{filename}.md",
                            mime="text/markdown"
                        )
                    else:
                        st.error(f"Error: {response.json().get('detail', 'Unknown error')}")

                except requests.exceptions.ConnectionError:
                    st.error("❌ Cannot connect to API. Make sure the backend is running on port 8000.")
                except Exception as e:
                    st.error(f"❌ Error: {str(e)}")
        else:
            st.warning("Please upload a file or paste Terraform code.")
    else:
        st.info("👆 Upload a Terraform file or paste code, then click Analyze")

# Example section
st.divider()
with st.expander("📝 Example Terraform (click to try)"):
    example_tf = '''# Example: AWS EC2 with security issues
provider "aws" {
  region = "us-east-1"
}

resource "aws_security_group" "web" {
  name = "web-sg"

  # ISSUE: Too permissive
  ingress {
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_instance" "web" {
  ami           = "ami-12345678"
  instance_type = "t2.xlarge"  # ISSUE: Probably oversized

  # ISSUE: No tags
  # ISSUE: No key_name for SSH
  # ISSUE: Using default VPC

  vpc_security_group_ids = [aws_security_group.web.id]
}

# ISSUE: No encryption
resource "aws_s3_bucket" "data" {
  bucket = "my-data-bucket"
}
'''
    st.code(example_tf, language="hcl")
    if st.button("Use this example"):
        st.session_state['example'] = example_tf
        st.rerun()
