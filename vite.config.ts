import path from 'path';
import { defineConfig, loadEnv } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig(({ mode }) => {
    const env = loadEnv(mode, '.', '');
    return {
      server: {
        port: 3000,
        host: '0.0.0.0',
        // 排除 backend 和 uploads 目录，避免 Vite 尝试处理上传的文件
        fs: {
          deny: ['backend', 'backend/**', 'uploads', 'uploads/**'],
          strict: false,
        },
        // 不监视 uploads 目录的变化
        watch: {
          ignored: ['**/uploads/**', '**/backend/**'],
        },
      },
      plugins: [react()],
      define: {
        'process.env.API_KEY': JSON.stringify(env.GEMINI_API_KEY),
        'process.env.GEMINI_API_KEY': JSON.stringify(env.GEMINI_API_KEY)
      },
      resolve: {
        alias: {
          '@': path.resolve(__dirname, '.'),
        }
      }
    };
});
