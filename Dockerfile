# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set a temporary working directory
WORKDIR /temp

# Copy the entire repository content. This handles cases where your code
# might be at the root, or inside a 'pvc-pro' subfolder.
COPY . .

# --- This is the new logic ---
# Check if app.py exists in a subfolder named 'pvc-pro'.
# If it does, we will make that our final working directory.
# If not, we will assume the files are in the root.
RUN if [ -d "pvc-pro" ] && [ -f "pvc-pro/app.py" ]; then \
        echo "Found app.py in subfolder. Moving files up."; \
        mv pvc-pro/* . ; \
    fi

# Set the final working directory
WORKDIR /app
COPY . /app/

# Install the requirements
RUN pip install --no-cache-dir -r requirements.txt

# This command can now find app.py because it's in /app
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "app:app"]

COPY firebase-adminsdk.json .
