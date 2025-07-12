# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the minimal test script into the container
COPY minimal_pyrebase_test.py .

# Run the minimal test script
CMD ["python", "minimal_pyrebase_test.py"]
