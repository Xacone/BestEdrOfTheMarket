<script>
  import '../app.css';
  import DarkMode from '$lib/components/DarkMode.svelte';
  import GitHubLink from '$lib/components/GitHubLink.svelte';
  import ListDetectionEvents from '$lib/components/ListDetectionEvents.svelte';
</script>

<div class="flex h-dvh flex-col gap-5 p-5">
  <header class="flex shrink-0 items-baseline justify-between">
    <div class="flex items-baseline gap-2">
      <h1 class="text-4xl font-bold">BEOTM</h1>
      <span class="text-primary text-2xl">GUI</span>
    </div>
    <div class="flex items-baseline">
      <!-- (later) Why not a panel / grid icon to manage the view -->
      <DarkMode></DarkMode>
      <div class="divider divider-horizontal"></div>
      <GitHubLink></GitHubLink>
    </div>
  </header>
  <ListDetectionEvents></ListDetectionEvents>
</div>
