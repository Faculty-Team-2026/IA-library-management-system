# Library Management System

A modern, full-stack library management system built with ASP.NET Core and React. This system helps libraries manage their books, users, memberships, and borrowing processes efficiently.

## Features

- 📚 Book Management
  - Add, edit, and remove books
  - Track book locations
  - Monitor book availability

- 👥 User Management
  - User registration and authentication
  - Role-based access control (Librarians, Members)
  - User profile management

- 📖 Borrowing System
  - Book borrowing and returns
  - Borrowing history
  - Request management

- 💳 Membership Management
  - Different membership types
  - Membership status tracking
  - Membership requests

- 💬 Real-time Chat
  - Communication between users
  - Instant notifications
  - SignalR integration

- 🗺️ Location Services
  - Book location tracking
  - Interactive maps using Leaflet

## Technology Stack

### Backend
- ASP.NET Core 9.0
- Entity Framework Core
- SQL Server
- SignalR for real-time communication
- JWT Authentication

### Frontend
- React 18
- TypeScript
- Vite
- TailwindCSS
- Material-UI
- Leaflet for maps
- Axios for API communication

## Prerequisites

- .NET 9.0 SDK
- Node.js (Latest LTS version)
- SQL Server
- Git

## Getting Started

1. Clone the repository:
   ```bash
   git clone https://github.com/Faculty-Team-2026/IA-library-management-system.git
   cd IA-library-management-system
   ```

2. Set up the backend:
   ```bash
   cd BackEnd
   dotnet restore
   dotnet ef database update
   dotnet run
   ```

3. Set up the frontend:
   ```bash
   cd FrontEnd
   npm install
   npm run dev
   ```

4. Open your browser and navigate to `http://localhost:5173`

## Project Structure

```
├── BackEnd/                 # ASP.NET Core backend
│   ├── Controllers/        # API endpoints
│   ├── Models/            # Database entities
│   ├── Services/          # Business logic
│   ├── DTOs/             # Data transfer objects
│   └── Hubs/             # SignalR hubs
├── FrontEnd/               # React frontend
│   ├── src/
│   │   ├── components/   # Reusable components
│   │   ├── Pages/       # Page components
│   │   ├── Services/    # API services
│   │   └── utils/       # Utility functions
│   └── public/           # Static assets
```

## API Documentation

The API endpoints are documented using Swagger. When running the backend, navigate to:
```
http://localhost:5000/swagger
```

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Faculty Team 2026
- All contributors who participated in this project
