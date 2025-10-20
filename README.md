# Authentication Service

A secure, scalable authentication microservice built with Spring Boot 3, Spring Security, JWT, and MongoDB.

## Features

- 🔐 JWT-based authentication
- 🔄 Refresh token mechanism
- 🔒 Role-based access control (USER, ADMIN)
- 🛡️ Password encryption with BCrypt
- 🗄️ MongoDB for data persistence
- 📝 Swagger/OpenAPI documentation
- 🧪 Comprehensive error handling
- 🚀 Ready for microservice architecture

## Tech Stack

- **Java 17**
- **Spring Boot 3.5.6**
- **Spring Security**
- **JWT (JSON Web Tokens)**
- **MongoDB**
- **Maven**
- **Lombok**

## Prerequisites

- Java 17 or higher
- Maven 3.6.0 or higher
- MongoDB 4.4 or higher
- (Optional) Docker & Docker Compose

## Getting Started

### 1. Clone the repository

```bash
git clone https://github.com/yourusername/auth-service.git
cd auth-service
```

### 2. Configure Environment

Create a `.env` file in the root directory with the following variables:

```env
MONGODB_URI=mongodb://localhost:27017/auth_db
JWT_SECRET=your-256-bit-secret
```

### 3. Run with Docker (Recommended)

```bash
docker-compose up --build
```

### 4. Run Locally

1. Start MongoDB service
2. Build and run the application:

```bash
mvn spring-boot:run
```

The application will be available at `http://localhost:8080`

## API Endpoints

### Authentication

| Method | Endpoint | Description |
|--------|----------|-------------|
| POST   | `/api/v1/auth/register` | Register a new user |
| POST   | `/api/v1/auth/authenticate` | Login and get JWT token |
| POST   | `/api/v1/auth/refresh-token` | Refresh access token |

### Example Requests

#### Register a new user

```http
POST /api/v1/auth/register
Content-Type: application/json

{
    "firstName": "John",
    "lastName": "Doe",
    "email": "john@example.com",
    "password": "password123"
}
```

#### Login

```http
POST /api/v1/auth/authenticate
Content-Type: application/json

{
    "email": "john@example.com",
    "password": "password123"
}
```

#### Response

```json
{
    "access_token": "eyJhbGciOiJIUzI1NiJ9...",
    "refresh_token": "eyJhbGciOiJIUzI1NiJ9...",
    "email": "john@example.com",
    "role": "USER"
}
```

## Security

- All endpoints except `/api/v1/auth/**` are secured
- Include JWT token in the `Authorization` header for protected endpoints:
  ```
  Authorization: Bearer <your-jwt-token>
  ```
- Passwords are encrypted using BCrypt
- JWT tokens expire after 24 hours (configurable)
- Refresh tokens expire after 7 days (configurable)

## Configuration

Edit `src/main/resources/application.yml` to modify:

- Server port
- MongoDB connection
- JWT settings
- Logging levels

## Development

### Build

```bash
mvn clean install
```

### Run Tests

```bash
mvn test
```

### Code Style

This project uses:
- Google Java Style Guide
- 4 spaces for indentation
- 120 character line length

## Integration with Other Services

To integrate this authentication service with other microservices:

1. Add the following dependency to your service's `pom.xml`:

```xml
<dependency>
    <groupId>org.springframework.cloud</groupId>
    <artifactId>spring-cloud-starter-openfeign</artifactId>
</dependency>
```

2. Create a Feign client to communicate with the auth service:

```java
@FeignClient(name = "auth-service", url = "${auth.service.url}")
public interface AuthServiceClient {
    
    @PostMapping("/api/v1/auth/validate")
    UserInfo validateToken(@RequestHeader("Authorization") String token);
}
```

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

For support, please open an issue in the GitHub repository.
