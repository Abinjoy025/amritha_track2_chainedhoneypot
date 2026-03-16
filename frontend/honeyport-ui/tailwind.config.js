/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      colors: {
        cyber: {
          900: '#0a0f1e',
          800: '#0d1529',
          700: '#111d3a',
        },
      },
    },
  },
  plugins: [],
}
