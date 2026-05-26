/** @type {import('tailwindcss').Config} */
export default {
  content: ["./index.html", "./src/**/*.{svelte,ts,js}"],
  theme: {
    extend: {
      colors: {
        kmitl: {
          50: "#eef5ff",
          100: "#d9e7ff",
          500: "#1f4e9d",
          600: "#193f7e",
          700: "#143367",
        },
      },
      fontFamily: {
        sans: ["Inter", "system-ui", "sans-serif"],
      },
    },
  },
  plugins: [],
};
