# Use an official Python runtime as a parent image
FROM python:3.9-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file and install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# CORRECTED COMMAND:
# Use "sh -c" to ensure the $PORT environment variable is expanded by the shell.
CMD ["sh", "-c", "streamlit run app.py --server.port $PORT"]