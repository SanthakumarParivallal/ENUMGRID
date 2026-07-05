// Flat ESLint config for the ENUMGRID operator UI (React 18 + Vite, JS/JSX).
// Static-analysis gate: JS correctness (@eslint/js), React + the new JSX runtime,
// the two Rules of Hooks, and jsx-a11y accessibility lint. Runs in CI and via
// `npm run lint`.
import js from '@eslint/js';
import react from 'eslint-plugin-react';
import reactHooks from 'eslint-plugin-react-hooks';
import jsxA11y from 'eslint-plugin-jsx-a11y';
import globals from 'globals';

export default [
  { ignores: ['dist/**', 'node_modules/**', 'coverage/**'] },
  js.configs.recommended,
  {
    files: ['**/*.{js,jsx}'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      parserOptions: { ecmaFeatures: { jsx: true } },
      globals: { ...globals.browser },
    },
    settings: { react: { version: 'detect' } },
    plugins: { react, 'react-hooks': reactHooks, 'jsx-a11y': jsxA11y },
    rules: {
      ...react.configs.flat.recommended.rules,
      ...react.configs.flat['jsx-runtime'].rules, // Vite's automatic JSX runtime — no `import React` needed
      ...jsxA11y.flatConfigs.recommended.rules,
      'react-hooks/rules-of-hooks': 'error',
      'react-hooks/exhaustive-deps': 'warn',
      'react/prop-types': 'off', // this project doesn't use prop-types
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
      'no-console': ['warn', { allow: ['warn', 'error'] }], // intentional diagnostics only
    },
  },
  {
    // Node-context files (build config + tests run under Node/Vitest).
    files: ['**/*.test.{js,jsx}', '*.config.js'],
    languageOptions: { globals: { ...globals.node } },
  },
];
