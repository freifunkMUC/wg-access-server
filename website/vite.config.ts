import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import svgr from 'vite-plugin-svgr'


export default defineConfig({
        plugins: [react(), svgr()],
    build: {
      outDir: "build",
    },
        resolve: {
            tsconfigPaths: true,
        },
    server: {
        proxy: {
            '/api': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                secure: false
            },
            '/signin': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                secure: false
            },
            '/signout': {
                target: 'http://localhost:8000',
                changeOrigin: true,
                secure: false
            }
        }
    }
  });
