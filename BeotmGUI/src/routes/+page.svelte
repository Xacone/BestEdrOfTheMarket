<script lang="ts">
  import '../app.css';
  import DarkMode from '$lib/components/DarkMode.svelte';
  import GitHubLink from '$lib/components/GitHubLink.svelte';
  import ListDetectionEvents from '$lib/components/list/ListDetectionEvents.svelte';
  import DetectionEventDetails from '$lib/components/details/DetectionEventDetails.svelte';
  import '../lib/i18n.js';
  import { t, locale } from 'svelte-i18n';
  import Toast from '$lib/components/Toast.svelte';
  import { initToastManager, ToastManager } from '$lib/logic/toast.svelte';
  import { EventsManager, initEventManager } from '$lib/logic/events-management.svelte';

  function toggleMagic() {
    locale.set($locale === 'fr' ? 'en' : 'fr');
  }

  initToastManager(new ToastManager());
  initEventManager(new EventsManager());
</script>

<svelte:head>
  <title>BeotmGUI</title>
</svelte:head>

<!-- TODO: improve keyboard navigation -->
<div class="flex h-dvh flex-col gap-5 p-5">
  <header class="flex shrink-0 items-baseline justify-between">
    <div class="flex items-baseline gap-2">
      <h1 class="text-4xl font-bold">{$t('beotm')}</h1>
      <button onclick={() => toggleMagic()} class="text-primary text-2xl">{$t('gui')}</button>
    </div>
    <div class="flex items-baseline">
      <DarkMode></DarkMode>
      <div class="divider divider-horizontal"></div>
      <GitHubLink></GitHubLink>
    </div>
  </header>
  <div class="flex h-full w-full gap-5 overflow-hidden">
    <ListDetectionEvents></ListDetectionEvents>
    <DetectionEventDetails></DetectionEventDetails>
  </div>
</div>
<Toast></Toast>
