<script lang="ts">
  import Sun from '@lucide/svelte/icons/sun';
  import Moon from '@lucide/svelte/icons/moon';

  import { onMount } from 'svelte';
  type Theme = 'light' | 'dark';
  let theme: Theme = $state('light');
  const storageKey = 'color-theme';
  let mounted = false;

  const themeSelection: Record<Theme, string> = {
    light: 'emerald',
    dark: 'night',
  };

  const getCurrentTheme = (): Theme => {
    const storedTheme = localStorage.getItem(storageKey);
    if (storedTheme && ['light', 'dark'].includes(storedTheme)) {
      return storedTheme as Theme;
    }
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
  };

  onMount(() => {
    theme = getCurrentTheme();
    mounted = true;
  });

  $effect(() => {
    if (!mounted) {
      // The local storage update should only be available once the theme has been retried a first time.
      return;
    }
    document.documentElement.setAttribute('data-theme', themeSelection[theme]);
    localStorage.setItem(storageKey, theme);
  });

  const toggleTheme = () => {
    theme = theme === 'light' ? 'dark' : 'light';
  };
</script>

<label class="toggle text-base-content">
  <input
    type="checkbox"
    onclick={toggleTheme}
    checked={theme === 'dark'}
    class="theme-controller"
  />

  <Sun aria-label="light" size="18" />
  <Moon aria-label="dark" size="18" />
</label>
