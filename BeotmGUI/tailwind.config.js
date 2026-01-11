// tailwind.config.js
/** @type {import('tailwindcss').Config} */
export const content = [
  './src/**/*.{html,js,svelte,ts}', // Adjust depending on where your components live
];
// To use when classes are hard to parse.
// That's why we advise to declare them explicitly in the code instead, for a better maintainability (see graphical-events for instance)
export const safelist = [];
