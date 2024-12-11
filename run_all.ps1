# Check if requirements.txt exists
if (!(Test-Path -Path "requirements.txt")) {
    Write-Host "requirements.txt not found!"
    exit 1
}

if (!(Test-Path -Path "AWS_access.txt")) {
    Write-Host "AWS_access.txt not found!"
    exit 1
}

# Create a virtual environment in the 'venv' folder
python -m venv venv

# Activate the virtual environment
# Note: The activate script for Windows is located in venv\Scripts\Activate.ps1
& ".\venv\Scripts\Activate.ps1"

# Install the packages from requirements.txt
pip install -r requirements.txt

#Write-Host "Virtual environment set up and packages installed successfully."

python main.py
#deactivate