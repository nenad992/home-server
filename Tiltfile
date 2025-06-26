# Use docker-compose for local development
docker_compose('docker-compose.dev.yml')

# Build the Docker image and connect it to the service
docker_build('home-server', '.', live_update=[
    sync('.', '/app'),
    run('pip install -r requirements.txt', trigger=['requirements.txt'])
])

# Configure the Docker Compose resource
dc_resource('home-server-dev')

