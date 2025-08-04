# --- Development Stage ---
FROM node:20-bullseye AS development

WORKDIR /usr/src/app

# Install Chromium and fonts required by Puppeteer
RUN apt-get update && apt-get install -y \
    chromium \
    fonts-freefont-ttf \
    ca-certificates \
    --no-install-recommends && \
    apt-get clean && rm -rf /var/lib/apt/lists/*

# Puppeteer Chromium path
ENV PUPPETEER_EXECUTABLE_PATH=/usr/bin/chromium

COPY package*.json ./

# Use latest stable npm version
RUN npm install -g npm@latest

# Install all dependencies (dev + prod)
RUN npm install

COPY . .

RUN npm run build

# --- Production Stage ---
FROM node:20-bullseye AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

COPY package*.json ./

# Install production-only dependencies
RUN npm install -g npm@latest && npm install --omit=dev

# Copy only the built app
COPY --from=development /usr/src/app/dist ./dist

CMD ["node", "dist/apps/notification-service/main"]
