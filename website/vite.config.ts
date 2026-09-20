import { defineConfig } from 'vitest/config'
import react from '@vitejs/plugin-react'
import svgr from 'vite-plugin-svgr'


export default defineConfig({
        plugins: [react(), svgr()],
    build: {
      outDir: "build",
    },
    test: {
        // components are rendered into a DOM, the pure helpers do not care
        environment: 'jsdom',
        include: ['src/**/*.test.{ts,tsx}'],
        setupFiles: ['src/test-setup.ts'],
        restoreMocks: true,
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
