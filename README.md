# Auth-Py

Hey! 👋 This is my proof of concept (PoC) for a modern authentication service built with FastAPI. I wanted to explore and implement various auth patterns and RFC standards, focusing on real-world security practices.

Oh, and if you're into Rust, I've got a simpler version of this over at [auth-rs](https://github.com/xosnrdev/auth-rs.git). It was my first take on this idea, but this Python version is where I really got to dive deep into the authentication concepts.

## What's This About?

This project showcases a production-ready approach to authentication and authorization. While it started as a PoC, it's grown into something I'm pretty proud of. The core features are solid and working well, though I've got some exciting ideas for improvements (check out [TODO.md](TODO.md) if you're curious about what's next!).

## Features

- Email/password authentication (because classics never die)
- Social login with Google and Apple
- JWT-based auth with refresh tokens
- Role-based access control (RBAC)
- Rate limiting to keep things safe
- Detailed audit logging
- Email verification flow
- Password reset system

## Tech Stack

- Python 3.13+
- FastAPI
- PostgreSQL
- Redis
- SQLAlchemy
- Pydantic
- Docker

## Want to Try It?

### Quick Start with Docker

```bash
# Grab the code
git clone https://github.com/xosnrdev/auth-py.git
cd auth-py

# Set up your environment
cp .env.example .env
# Customize .env with your settings
# API runs on port 8000 by default

# Fire it up!
docker compose up -d
```

You'll find the API running at http://localhost:{API_PORT} (defaults to 8000)

### Local Development

```bash
# Get the code
git clone https://github.com/xosnrdev/auth-py.git
cd auth-py

# Set up uv (it's faster than pip!)
curl -LsSf https://astral.sh/uv/install.sh | sh

# Create your environment
uv venv
source .venv/bin/activate  # Linux/Mac
# or
.venv\Scripts\activate  # Windows

# Install what you need
uv sync
# or stick with pip if you prefer
pip install -r requirements.txt

# Configure your setup
cp .env.example .env
# Add your settings to .env

# Start Postgres and Redis
docker compose -f docker-compose.dev.yml up -d

# Start coding!
fastapi dev
```

## Want to Help?

Got ideas? Found a bug? Want to contribute? Awesome! Here's how:

1. Fork it
2. Branch it
3. Code it
4. Push it
5. PR it

I'm always open to fresh perspectives and improvements!

## License

See [LICENSE](LICENSE) for details.

## Security Heads Up

While this project follows security best practices and implements proper RFC standards, it's still a PoC. I'd love feedback on the security aspects, but maybe don't use it for your bank's authentication system just yet 😉

Found something security-related? Drop me a line at [hello@xosnrdev.tech](mailto:hello@xosnrdev.tech).