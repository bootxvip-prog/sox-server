FROM node:22-alpine
WORKDIR /app
COPY . .
ENV DATA_DIR=/data
EXPOSE 3000
CMD ["node","server.js"]
