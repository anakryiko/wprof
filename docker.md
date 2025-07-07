# Docker setup for wprof on macOS

```bash
# Install Docker Desktop
brew install --cask docker

# Start Docker Desktop from Applications, wait for whale icon

# Build development image
docker build -t wprof-build .

# Run container with code mounted
docker run -it --rm -v $(pwd):/src wprof-build bash

# Build inside container
make -j$(nproc) -C src

# Optional alias for convenience
alias wprof-build='docker run -it --rm -v $(pwd):/src wprof-build'
```
