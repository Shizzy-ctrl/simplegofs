# FileServer

A simple, secure file server written in Go.

## Features

- Basic Authentication
- File browsing and previewing
- Secure file download
- Docker support

## Prerequisites

- Go 1.25+ (for local development)
- Docker & Docker Compose (for containerized deployment)

## Setup

1.  **Clone the repository:**
    ```bash
    git clone <repository-url>
    cd fileserver
    ```

2.  **Configure Users:**
    Create a `.env` file in the root directory. You can start by copying the example:
    ```bash
    cp .env.example .env
    ```

    Open `.env` and add users in the format `USER_username=password`.
    ```env
    USER_admin=admin123
    USER_guest=securepassword
    ```

3.  **Add Files:**
    Place the files you want to share in the `files/` directory.
    ```bash
    mkdir -p files
    cp /path/to/your/file.pdf files/
    ```

## Running with Docker

1.  **Build and Run:**
    ```bash
    docker-compose up -d --build
    ```

2.  **Access:**
    Open your browser and navigate to `http://localhost:8080`.
    Log in with the credentials defined in your `.env` file.

## Running Locally

1.  **Run:**
    ```bash
    go run main.go
    ```
    The server will start on port 8080.

## Project Structure

-   `main.go`: Main application logic.
-   `static/`: Static assets (CSS).
-   `files/`: Directory for shared files.
-   `.env`: Configuration file for users (not committed).
