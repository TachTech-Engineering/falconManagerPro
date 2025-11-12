
# Stage 1: Build the React app ----
FROM node:18 AS build

WORKDIR /app

# Copy package files and install dependencies
COPY package.json package-lock.json ./
RUN npm install --no-audit --no-fund

# Copy the rest of the frontend source and build
COPY . .
RUN npm run build

# ---- Stage 2: Serve with Nginx ----
FROM nginx:alpine

# Copy your custom Nginx config (now in repo root)
COPY nginx.conf /etc/nginx/conf.d/default.conf

# Copy the React build output to Nginx’s HTML directory
COPY --from=build /app/build /usr/share/nginx/html

EXPOSE 80

CMD ["nginx", "-g", "daemon off;"]






























