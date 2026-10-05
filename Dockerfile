FROM node:22-alpine

WORKDIR /app

# Copy package.json dan package-lock.json
COPY package*.json ./

# Install dependencies (hanya production)
RUN npm ci --omit=dev

# Copy seluruh kode aplikasi
COPY . .

# Buat folder data untuk SQLite (jika belum ada)
RUN mkdir -p data

# Expose port aplikasi
EXPOSE 3000

# Jalankan aplikasi
CMD ["npm", "start"]