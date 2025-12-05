import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

// https://vite.dev/config/
export default defineConfig({
  plugins: [react()],
  server: {
    allowedHosts: ['knox-mimosaceous-maris.ngrok-free.dev'],
    hmr: {
      overlay: false
    }
  }
})
