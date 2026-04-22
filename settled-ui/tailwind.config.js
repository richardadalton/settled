/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/client/**/*.{ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'monospace'],
      },
      colors: {
        surface: {
          0: '#0d0f14',
          1: '#13161e',
          2: '#1a1e29',
          3: '#222636',
        },
        accent: {
          blue:  '#4f8ef7',
          green: '#3ecf8e',
          red:   '#f76f6f',
          amber: '#f0a733',
          purple:'#a78bfa',
        },
      },
    },
  },
  plugins: [],
};
