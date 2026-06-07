/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Industrial cockpit palette ---------------------------------------
        // Themeable chassis + neutrals driven by CSS variables (see index.css),
        // so a single `<html data-theme>` swap repaints the whole UI (dark cockpit
        // ⇄ light paper). Using `rgb(var(--x) / <alpha-value>)` keeps every
        // opacity modifier (e.g. bg-steel-850/60) working automatically.
        steel: {
          950: 'rgb(var(--steel-950) / <alpha-value>)', // chassis / app background
          900: 'rgb(var(--steel-900) / <alpha-value>)', // raised panels
          850: 'rgb(var(--steel-850) / <alpha-value>)', // panel header strips
          800: 'rgb(var(--steel-800) / <alpha-value>)', // hover / active row
        },
        // The neutral text/border ramp is themeable too (the light theme inverts
        // it: low shades become dark ink, high shades become light hairlines).
        slate: {
          100: 'rgb(var(--slate-100) / <alpha-value>)',
          200: 'rgb(var(--slate-200) / <alpha-value>)',
          300: 'rgb(var(--slate-300) / <alpha-value>)',
          400: 'rgb(var(--slate-400) / <alpha-value>)',
          500: 'rgb(var(--slate-500) / <alpha-value>)',
          600: 'rgb(var(--slate-600) / <alpha-value>)',
          700: 'rgb(var(--slate-700) / <alpha-value>)',
          800: 'rgb(var(--slate-800) / <alpha-value>)',
        },
        // Cyberpunk Amber — primary "energized / in-progress" accent
        amber: {
          DEFAULT: '#FFB300',
          glow: '#FFC233',
          dim: '#7a5600',
        },
        // Matrix Green — healthy / up / open / success
        matrix: {
          DEFAULT: '#00E676',
          dim: '#0a5c36',
        },
        // Crimson — critical errors, filtered/blocked ports, hosts down
        crimson: {
          DEFAULT: '#D32F2F',
          dim: '#5a1a1a',
        },
      },
      fontFamily: {
        // Sans for chrome (labels, buttons), mono for all machine data.
        sans: ['Inter', 'ui-sans-serif', 'system-ui', 'sans-serif'],
        mono: ['"Fira Code"', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'monospace'],
      },
      boxShadow: {
        'glow-amber': '0 0 0 1px rgba(255,179,0,0.35), 0 0 18px -2px rgba(255,179,0,0.45)',
        'glow-matrix': '0 0 0 1px rgba(0,230,118,0.30), 0 0 18px -4px rgba(0,230,118,0.40)',
        'glow-crimson': '0 0 0 1px rgba(211,47,47,0.35), 0 0 18px -4px rgba(211,47,47,0.45)',
        'inset-panel': 'inset 0 1px 0 0 rgba(148,163,184,0.06)',
      },
      keyframes: {
        'pulse-glow': {
          '0%, 100%': { opacity: '1' },
          '50%': { opacity: '0.35' },
        },
        'stripe-move': {
          '0%': { backgroundPosition: '0 0' },
          '100%': { backgroundPosition: '28px 0' },
        },
        'radar-sweep': {
          '0%': { transform: 'rotate(0deg)' },
          '100%': { transform: 'rotate(360deg)' },
        },
        'scan-line': {
          '0%': { transform: 'translateX(-110%)' },
          '100%': { transform: 'translateX(110%)' },
        },
        'expand-in': {
          '0%': { opacity: '0', transform: 'translateY(-4px)' },
          '100%': { opacity: '1', transform: 'translateY(0)' },
        },
        flicker: {
          '0%, 19%, 21%, 100%': { opacity: '1' },
          '20%': { opacity: '0.4' },
        },
      },
      animation: {
        'pulse-glow': 'pulse-glow 1.5s ease-in-out infinite',
        stripe: 'stripe-move 0.7s linear infinite',
        radar: 'radar-sweep 3s linear infinite',
        'scan-line': 'scan-line 2.2s ease-in-out infinite',
        'expand-in': 'expand-in 0.18s ease-out',
        flicker: 'flicker 4s linear infinite',
      },
    },
  },
  plugins: [],
};
