FROM node:22-alpine

WORKDIR /app

COPY server/package*.json ./

RUN npm install --omit=dev

COPY server/ .

EXPOSE 4000

CMD ["node", "index.js"]
