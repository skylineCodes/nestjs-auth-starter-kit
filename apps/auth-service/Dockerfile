# --- Development Stage ---
FROM node:20-bullseye AS development

WORKDIR /usr/src/app

# Copy package files early for better caching
COPY package*.json ./

# Set npm timeouts to handle slow network issues
RUN npm config set fetch-retry-maxtimeout 60000 \
 && npm config set fetch-timeout 60000 \
 && npm install -g npm@latest \
 && npm install

# Copy remaining source files
COPY . .

# Build the project
RUN npm run build


# --- Production Stage ---
FROM node:20-bullseye AS production

ARG NODE_ENV=production
ENV NODE_ENV=${NODE_ENV}

WORKDIR /usr/src/app

# Copy only package files and install production deps
COPY package*.json ./
RUN npm install -g npm@latest \
 && npm install --omit=dev

# Copy built output from development stage
COPY --from=development /usr/src/app/dist ./dist

# Start the application
CMD ["node", "dist/apps/auth-service/main"]
