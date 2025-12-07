import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0', // Allow access from any device on network
    port: 5173,
    allowedHosts: ['knox-mimosaceous-maris.ngrok-free.dev'],
    hmr: {
      overlay: false
    },
    proxy: {
      '/api': {
        target: 'http://localhost:5205',
        changeOrigin: true,
        secure: false,
      },
      '/chathub': {
        target: 'http://localhost:5205',
        changeOrigin: true,
        secure: false,
        ws: true,
      },
      '/sessionhub': {
        target: 'http://localhost:5205',
        changeOrigin: true,
        secure: false,
        ws: true,
      }
    }
  }
})
