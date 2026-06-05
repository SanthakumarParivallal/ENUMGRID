/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx}'],
  theme: {
    extend: {
      colors: {
        // Industrial cockpit palette ---------------------------------------
        // Strict dark-mode chassis built on slate, with three signal accents.
        steel: {
          950: '#020617', // chassis / app background (bg-slate-950)
          900: '#0b1220', // raised panels
          850: '#0e1626', // panel header strips
          800: '#162033', // hover / active row
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
