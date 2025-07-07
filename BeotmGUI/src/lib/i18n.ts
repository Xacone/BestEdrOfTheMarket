import { addMessages, init, getLocaleFromNavigator, register } from 'svelte-i18n';

// Enregistre les fichiers de traduction
register('en', () => import('../resources/i18n/en.json'));
register('fr', () => import('../resources/i18n/fr.json'));

// Initialise la config
init({
  fallbackLocale: 'en',
});
