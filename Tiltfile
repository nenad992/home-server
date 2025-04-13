# Build image
docker_build('home-server', '.')

# Pokreni app u kontejneru sa mount i port (automatski ugasi prethodni)
local_resource(
    'flask-app',
    'docker run --rm -p 8899:8888 -v .:/app home-server',
    deps=['.'],
    auto_init=True
)

