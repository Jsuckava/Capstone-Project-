FROM node:20-slim

# Install system dependencies for node-canvas, bcrypt, etc. if needed
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    python3-venv \
    make \
    g++ \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

RUN python3 -m venv /opt/blockgo-venv
ENV PATH="/opt/blockgo-venv/bin:$PATH"

# Copy package files
COPY package*.json ./
COPY requirements.txt ./

# Install production dependencies exactly from the lockfile
RUN npm ci --omit=dev
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# The same immutable image supplies six independently deployed process types.
EXPOSE 4000 4001 4002 4003 4004 4005

# Set environment defaults
ENV PORT=4000
ENV NODE_ENV=production
ENV NODE_OPTIONS="--max-old-space-size=256 --expose-gc"

HEALTHCHECK --interval=30s --timeout=5s --start-period=30s --retries=3 CMD node -e "const http=require('http');const req=http.get({host:'127.0.0.1',port:process.env.PORT||4000,path:'/api/health',timeout:4000},res=>process.exit(res.statusCode===200?0:1));req.on('timeout',()=>req.destroy(new Error('timeout')));req.on('error',()=>process.exit(1));"

# Run the middleware
CMD ["node", "middleware.js"]
