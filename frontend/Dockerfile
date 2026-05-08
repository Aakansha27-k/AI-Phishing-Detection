FROM node:20-alpine

WORKDIR /app

COPY package*.json ./
RUN npm install

COPY . .

# We use dev mode for the docker-compose to allow hot-reloading
CMD ["npm", "run", "dev"]
