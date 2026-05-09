FROM node:22-alpine
WORKDIR /app
COPY . .
RUN npm ci --only=production
CMD ["node", "index.js"]
