<script lang="ts">
  import '../app.css';
  import DarkMode from '$lib/components/DarkMode.svelte';
  import GitHubLink from '$lib/components/GitHubLink.svelte';
  import ListDetectionEvents from '$lib/components/ListDetectionEvents.svelte';
  import { detectedEvents } from '$lib/logic/poll-events.svelte';
  import { type DetectionEvent } from '$lib/schemas/detection-events';
  import DetectionEventDetails from "$lib/components/DetectionEventDetails.svelte";
  import "../lib/i18n.js";
  import { isLoading, t, locale} from 'svelte-i18n';

  let selectedEvent: DetectionEvent | null = $state(null);

 function toggleMagic() {
   locale.set($locale === 'fr' ? 'en' : 'fr');
  }
</script>

{#if !$isLoading}
  <div class="flex h-dvh flex-col gap-5 p-5">
    <header class="flex shrink-0 items-baseline justify-between">
      <div class="flex items-baseline gap-2">
        <h1 class="text-4xl font-bold">{ $t('beotm') }</h1>
        <button onclick="{() => toggleMagic()}" class="text-primary text-2xl">{ $t('gui') }</button>
      </div>
      <div class="flex items-baseline">
        <!-- (later) Why not a panel / grid icon to manage the view -->
        <DarkMode></DarkMode>
        <div class="divider divider-horizontal"></div>
        <GitHubLink></GitHubLink>
      </div>
    </header>
    <div class="flex h-full w-full gap-5 overflow-hidden">
      <ListDetectionEvents {detectedEvents} bind:selectedEvent></ListDetectionEvents>
      <DetectionEventDetails bind:selectedEvent></DetectionEventDetails>
    </div>
  </div>
{/if}
