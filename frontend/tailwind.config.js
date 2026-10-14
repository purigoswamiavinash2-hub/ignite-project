/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        navy: {
          900: '#0b132b',
          800: '#1c2541',
          700: '#171f38',
          600: '#263359',
          500: '#2b3a67',
        },
        cyan: {
          400: '#4cc9f0',
          500: '#38bdf8',
        },
        brand: {
          blue: '#4895ef',
        },
        status: {
          critical: '#ef4444',
          high: '#f97316',
          medium: '#f59e0b',
          low: '#10b981'
        }
      },
      fontFamily: {
        sans: ['Inter', 'system-ui', 'sans-serif'],
        mono: ['JetBrains Mono', 'monospace'],
      }
    },
  },
  plugins: [],
}
