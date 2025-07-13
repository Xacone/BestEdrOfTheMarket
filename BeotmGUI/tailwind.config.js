// tailwind.config.js
/** @type {import('tailwindcss').Config} */
export const content = [
  './src/**/*.{html,js,svelte,ts}', // Adjust depending on where your components live
];
export const safelist = ['alert-success', 'alert-error', 'alert-warning', 'alert-info'];
