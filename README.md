# Secure Monitoring Management System - PayamPardaz Internship

This repository contains the implementation of the **Secure Monitoring Management System** developed during my internship as a Software Engineer at **PayamPardaz** in Isfahan, Iran (June 2020 - September 2020). The project was built using **Python Django** and served as a backend for managing and monitoring company products securely and efficiently.

## Project Overview

### Description
The **Secure Monitoring Management System** was developed to provide real-time monitoring and management capabilities for PayamPardaz's products. The solution was tailored to meet specific security requirements and support various custom features for better product control. The system included:
- **Backend Development** using **Python Django** for robust and secure data handling.
- An **NGINX web server** for handling HTTP requests efficiently.
- Support for **real-time connections** and **security features** for secure communication between users and devices.

### Key Features
- **Python Django Backend**: The backend was developed with Django, which facilitated rapid development while maintaining high security and scalability.
- **NGINX Web Server Integration**: Configured **NGINX** as the web server to manage incoming traffic, improve performance, and provide load balancing for the Django backend.
- **Real-Time Monitoring**: Integrated WebSockets to facilitate real-time data connections and updates, ensuring up-to-date information for monitoring purposes.
- **Custom Security Features**: Implemented various security measures, including **authentication mechanisms**, **encryption**, and **access control** to ensure secure communication between different components.

### Tools & Technologies
- **Python** and **Django** for backend development.
- **NGINX** for web server management.
- **SQLite/MySQL** as the database for data storage.
- **WebSockets** for real-time data transmission.
- **Docker** for containerization of services (optional).

## How to Set Up and Run the Project

### Prerequisites
- **Python 3.8+**
- **Django 3.x**
- **NGINX**
- **Docker** (optional)

### Installation Steps
1. **Clone the Repository**:
   ```bash
   git clone https://github.com/Pouria-D/CascadeManagement.git
   cd CascadeManagement
   ```

2. **Install Dependencies**:
   Install the required Python packages:
   ```bash
   pip install -r requirements.txt
   ```

3. **Database Setup**:
   Run migrations to set up the database:
   ```bash
   python manage.py migrate
   ```

4. **Run Development Server**:
   Start the Django development server:
   ```bash
   python manage.py runserver
   ```

5. **Configure NGINX** (Optional for Production):
   - Use the provided `nginx.conf` file to configure NGINX as a reverse proxy for the Django application.
   - Ensure you have set up SSL certificates for secure communication.

### Real-Time Monitoring Setup
- **WebSocket Integration**: The project uses WebSockets to facilitate real-time communication between the backend and the clients. Ensure that Django Channels is properly configured to support WebSockets.

### Docker Setup (Optional)
- A `Dockerfile` is provided to build the application container.
- Run the following command to build the Docker image:
  ```bash
  docker build -t cascade_management .
  ```
- Start the container using Docker Compose:
  ```bash
  docker-compose up
  ```

## Report
A complete report of the implementation details, including architectural decisions, security features, and technical challenges, is available in the `docs` folder as a PDF. This report includes:
- **System Architecture**: Overview of the architecture used, including backend components, data flow, and security layers.
- **Security Features**: Detailed discussion of implemented security measures.
- **Performance Metrics**: Evaluation of the system's performance under different conditions.

## Contact
For more details or questions regarding this project, feel free to contact me at [pouria.dadkhah@gmail.com](mailto:pouria.dadkhah@gmail.com).

---
Feel free to explore the project, use it for learning purposes, or contribute to improve the implementation!

