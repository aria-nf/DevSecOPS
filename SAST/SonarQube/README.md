# Sonar Qube
## Setup Manual
```bash
mkdir sonarqube
cd sonarqube

cat << `EOF` > docker-compose.yml
services:
  sonarqube:
    image: sonarqube:community
    container_name: sonarqube
    depends_on:
      - db
    ports:
      - "9000:9000"
    environment:
      SONAR_JDBC_URL: jdbc:postgresql://db:5432/sonar
      SONAR_JDBC_USERNAME: sonar
      SONAR_JDBC_PASSWORD: sonar
    volumes:
      - sonarqube_data:/opt/sonarqube/data
      - sonarqube_extensions:/opt/sonarqube/extensions
      - sonarqube_logs:/opt/sonarqube/logs

  db:
    image: postgres:15
    container_name: sonarqube_db
    environment:
      POSTGRES_USER: sonar
      POSTGRES_PASSWORD: sonar
      POSTGRES_DB: sonar
    volumes:
      - postgresql_data:/var/lib/postgresql/data

volumes:
  sonarqube_data:
  sonarqube_extensions:
  sonarqube_logs:
  postgresql_data:
EOF

docker compose config
docker compose up -d
docker compose ps

docker compose logs
```

## Setup Lab with ZIP
```bash
gdown https://drive.google.com/file/d/1Q8GxuCClc9vja-LsqIfRS4OjHo91aAI3/view?usp=sharing

unzip laravel-sast-lab.zip
cd laravel-sast-lab/

sudo sysctl -w vm.max_map_count=262144
sysctl vm.max_map_count

docker compose up -d
```

> open your browser and go to http://localhost:9000

login with credentials: admin:admin dan ubah pw sesuai yang di inginkan.

## Sonar Qube Dashboard
1. setelah itu create a local project
2. pilih Follows the instance's default (Previous version)
3. setelah itu buat token: sqp_566d4138740a8f100abf6044e24a30162e2d4961

## Sonar Qube CLI
lakukan SAST dengan cara masuk ke folder project kamu, lalu jalankan perintah berikut:

##### Via Docker
```bash
TOKEN=sqp_566d4138740a8f100abf6044e24a30162e2d4961
docker run --rm --network=host \
  -v "$(pwd):/usr/src" \
  sonarsource/sonar-scanner-cli \
  -Dsonar.projectKey=Laravel-SAST-Lab \
  -Dsonar.sources=. \
  -Dsonar.host.url=http://192.168.2.12:9000 \
  -Dsonar.token=$TOKEN
```

##### Via Local Installation
```bash
mkdir -p /tmp/sonar
cd /tmp/sonar
wget https://binaries.sonarsource.com/Distribution/sonar-scanner-cli/sonar-scanner-cli-5.0.1.3006-linux.zip
unzip sonar-scanner-cli-*.zip
export PATH=$PATH:$PWD/sonar-scanner-*/bin

cd -
sonar-scanner
```

## Hasil Analisa SAST
##### BEFORE


##### AFTER

---

#### Remove Image
```bash
docker rm -f sonarqube sonarqube_db
docker volume rm sonarqube_sonarqube_data sonarqube_sonarqube_extensions
```
