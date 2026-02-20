# Usar Node LTS estable
FROM node:22-alpine

# Crear carpeta de trabajo
WORKDIR /app

# Copiar package.json primero (mejor cache)
COPY package*.json ./

# Instalar solo dependencias de producción
RUN npm install --omit=dev

# Copiar resto del proyecto
COPY . .

# Exponer puerto (el que use tu server)
EXPOSE 3000

# Comando para iniciar la app
CMD ["node", "server.js"]