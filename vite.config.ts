import { defineConfig } from 'vite'
import { resolve } from 'path'

export default defineConfig({
  base: '/itservices-phishguard/',
  build: {
    outDir: 'dist',
    rollupOptions: {
      input: {
        main: resolve(__dirname, 'index.html'),
        auth: resolve(__dirname, 'auth.html'),
      },
    },
  },
})
