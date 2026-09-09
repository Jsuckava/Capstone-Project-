FROM node:20-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
# Setup Tailwind if needed
RUN npx tailwindcss init -p && \
    echo "module.exports = { content: ['./src/**/*.{js,jsx,ts,tsx}'], theme: { extend: {} }, plugins: [] };" > tailwind.config.js
RUN DISABLE_ESLINT_PLUGIN=true npm run build

FROM nginx:alpine
COPY --from=build /app/build /usr/share/nginx/html
# Add a custom nginx config to handle React Router (fallback to index.html)
RUN echo 'server { listen 80; location / { root /usr/share/nginx/html; index index.html; try_files $uri $uri/ /index.html; } }' > /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]